package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/config"
	"github.com/tetraneurons/reversebug/api/internal/db"
	"github.com/tetraneurons/reversebug/api/internal/mail"
	"github.com/tetraneurons/reversebug/api/internal/ratelimit"
	"github.com/tetraneurons/reversebug/api/internal/server"
	"github.com/tetraneurons/reversebug/api/internal/storage"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

func TestPhase5APIKeysBillingAndAdmin(t *testing.T) {
	ctx := context.Background()
	pool, err := db.Connect(ctx, testDBURL)
	if err != nil {
		t.Skipf("skipping integration tests, postgres not available: %v", err)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	tempDir := t.TempDir()
	stg, err := storage.NewLocal(tempDir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	cfg := &config.Config{
		Env:                    "development",
		PublicBaseURL:          "http://localhost:5173",
		AllowedOrigins:         []string{"http://localhost:5173"},
		CookieSecure:           false,
		SessionIdleTimeout:     time.Hour,
		SessionAbsoluteTimeout: 24 * time.Hour,
		DataEncryptionKey:      bytes.Repeat([]byte{0x42}, 32),
		APIKeyPepper:           bytes.Repeat([]byte{0x77}, 32),
		MaxUploadBytes:         50 * 1024 * 1024,
		StorageDir:             tempDir,
	}

	st := store.New(pool)
	auditLogger := audit.New(pool)
	mailer := &mail.Recorder{}
	limiter := ratelimit.NewMemory()

	srv, err := server.New(server.Deps{
		Config:   cfg,
		Store:    st,
		Storage:  stg,
		Audit:    auditLogger,
		Mailer:   mailer,
		Limiter:  limiter,
		Argon:    &fastArgon,
		SyncMail: true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	handler := srv.Routes()

	// Helper: HTTP request
	doReq := func(method, path string, body any, cookie *http.Cookie, csrf string, authHeader string) (*http.Response, map[string]any) {
		var reqBody *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			reqBody = bytes.NewReader(b)
		} else {
			reqBody = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, reqBody)
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		res := rec.Result()

		var resBody map[string]any
		if rec.Body.Len() > 0 && strings.Contains(res.Header.Get("Content-Type"), "application/json") {
			_ = json.Unmarshal(rec.Body.Bytes(), &resBody)
		}
		return res, resBody
	}

	// 1. Register user
	email := fmt.Sprintf("phase5_%d@example.com", time.Now().UnixNano())
	pwd := "SecurePassword123#!"
	regResp, regBody := doReq("POST", "/api/v1/auth/register", map[string]any{
		"email":        email,
		"password":     pwd,
		"display_name": "Phase5 Tester",
		"accept_terms": true,
	}, nil, "", "")
	if regResp.StatusCode != http.StatusAccepted {
		t.Fatalf("register failed (%d): %v", regResp.StatusCode, regBody)
	}

	// Extract email verification token
	lastMsg, ok := mailer.Last()
	if !ok {
		t.Fatal("expected email verification message")
	}
	tokenParts := strings.Split(lastMsg.Text, "token=")
	if len(tokenParts) < 2 {
		t.Fatalf("token missing in email body: %s", lastMsg.Text)
	}
	token := strings.Fields(tokenParts[1])[0]

	// Verify email
	vResp, _ := doReq("POST", "/api/v1/auth/verify-email", map[string]string{"token": token}, nil, "", "")
	if vResp.StatusCode != http.StatusOK {
		t.Fatalf("verify email failed: %d", vResp.StatusCode)
	}

	// 2. Sign in to obtain session cookie
	loginResp, loginBody := doReq("POST", "/api/v1/auth/login", map[string]string{
		"email":    email,
		"password": pwd,
	}, nil, "", "")
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login failed (%d): %v", loginResp.StatusCode, loginBody)
	}

	var sessionCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "rb_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie from login")
	}

	// 3. Fetch session for CSRF token & user info
	_, sessBody := doReq("GET", "/api/v1/auth/session", nil, sessionCookie, "", "")
	userObj := sessBody["user"].(map[string]any)
	userID := userObj["id"].(string)
	csrfToken := sessBody["csrf_token"].(string)

	// -----------------------------------------------------------------------
	// Test Subscriptions & Billing
	// -----------------------------------------------------------------------
	t.Run("Billing and Subscriptions", func(t *testing.T) {
		// 1. Get Subscription (should auto-provision free plan)
		res, body := doReq("GET", "/api/v1/billing/subscription", nil, sessionCookie, "", "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("get subscription failed (%d): %v", res.StatusCode, body)
		}
		if body["plan_id"] != "free" {
			t.Fatalf("expected free plan, got %v", body["plan_id"])
		}
		entitlements, ok := body["entitlements"].(map[string]any)
		if !ok || entitlements["scans_per_month"] == nil {
			t.Fatalf("expected free plan entitlements, got %v", body["entitlements"])
		}

		// 2. Upgrade to Pro plan
		upResp, upBody := doReq("POST", "/api/v1/billing/upgrade", map[string]string{
			"plan_id": "pro",
		}, sessionCookie, csrfToken, "")
		if upResp.StatusCode != http.StatusOK {
			t.Fatalf("upgrade failed (%d): %v", upResp.StatusCode, upBody)
		}
		if upBody["plan_id"] != "pro" {
			t.Fatalf("expected upgraded plan pro, got %v", upBody["plan_id"])
		}

		// 3. Cancel Subscription
		cResp, cBody := doReq("POST", "/api/v1/billing/cancel", nil, sessionCookie, csrfToken, "")
		if cResp.StatusCode != http.StatusOK {
			t.Fatalf("cancel failed (%d): %v", cResp.StatusCode, cBody)
		}

		// Verify cancel_at_period_end is true
		vResp, vBody := doReq("GET", "/api/v1/billing/subscription", nil, sessionCookie, "", "")
		if vResp.StatusCode != http.StatusOK {
			t.Fatalf("get subscription after cancel failed (%d): %v", vResp.StatusCode, vBody)
		}
		if vBody["cancel_at_period_end"] != true {
			t.Fatalf("expected cancel_at_period_end=true, got %v", vBody["cancel_at_period_end"])
		}
	})

	// -----------------------------------------------------------------------
	// Test API Keys (Creation, Bearer Auth, Revocation)
	// -----------------------------------------------------------------------
	var rawApiKey string
	var apiKeyID string

	t.Run("API Key Lifecycle & Bearer Authentication", func(t *testing.T) {
		// 1. Create API key
		days := 30
		cResp, cBody := doReq("POST", "/api/v1/api-keys", map[string]any{
			"name":            "CI Automation Key",
			"scopes":          []string{"scans:read", "scans:write", "projects:read"},
			"expires_in_days": days,
		}, sessionCookie, csrfToken, "")
		if cResp.StatusCode != http.StatusCreated {
			t.Fatalf("create api key failed (%d): %v", cResp.StatusCode, cBody)
		}
		rawApiKey = cBody["token"].(string)
		keyObj := cBody["api_key"].(map[string]any)
		apiKeyID = keyObj["id"].(string)

		if !strings.HasPrefix(rawApiKey, "rb_live_") {
			t.Fatalf("expected raw token with prefix rb_live_, got %s", rawApiKey)
		}

		// 2. List API keys
		lResp, lBody := doReq("GET", "/api/v1/api-keys", nil, sessionCookie, "", "")
		if lResp.StatusCode != http.StatusOK {
			t.Fatalf("list api keys failed (%d): %v", lResp.StatusCode, lBody)
		}
		items := lBody["items"].([]any)
		if len(items) == 0 {
			t.Fatal("expected at least 1 api key in list")
		}

		// 3. Authenticate with API Key using Bearer token (no cookie, no CSRF token)
		bearerHeader := "Bearer " + rawApiKey
		pResp, pBody := doReq("GET", "/api/v1/projects", nil, nil, "", bearerHeader)
		if pResp.StatusCode != http.StatusOK {
			t.Fatalf("bearer auth on projects failed (%d): %v", pResp.StatusCode, pBody)
		}

		// 4. Authenticate state-changing POST request with Bearer token (must bypass CSRF)
		projCreateResp, projCreateBody := doReq("POST", "/api/v1/projects", map[string]any{
			"name":              "API Key Created Project",
			"description":       "Created via Bearer token",
			"application_owner": "Automation Bot",
			"environment":       "production",
			"tags":              []string{"cli", "ci"},
		}, nil, "", bearerHeader)
		if projCreateResp.StatusCode != http.StatusCreated {
			t.Fatalf("bearer auth state-changing post failed (%d): %v", projCreateResp.StatusCode, projCreateBody)
		}

		// 5. Test invalid API key
		badResp, _ := doReq("GET", "/api/v1/projects", nil, nil, "", "Bearer rb_live_invalidkey00000000000000000000000000000000000000000")
		if badResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for invalid api key, got %d", badResp.StatusCode)
		}

		// 6. Revoke API key
		delResp, _ := doReq("DELETE", "/api/v1/api-keys/"+apiKeyID, nil, sessionCookie, csrfToken, "")
		if delResp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete api key failed with %d", delResp.StatusCode)
		}

		// 7. Verify revoked key is rejected
		revResp, _ := doReq("GET", "/api/v1/projects", nil, nil, "", bearerHeader)
		if revResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for revoked api key, got %d", revResp.StatusCode)
		}
	})

	// -----------------------------------------------------------------------
	// Test Admin Console & Hash-Chain Audit Verification
	// -----------------------------------------------------------------------
	t.Run("Administrator Console", func(t *testing.T) {
		// 1. Verify regular user is denied admin routes (403)
		denResp, _ := doReq("GET", "/api/v1/admin/stats", nil, sessionCookie, "", "")
		if denResp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for non-admin on /admin/stats, got %d", denResp.StatusCode)
		}

		// 2. Elevate user to system_admin in DB
		_, err = pool.Exec(ctx, "UPDATE users SET platform_role = 'system_admin' WHERE id = $1;", userID)
		if err != nil {
			t.Fatalf("elevate user role: %v", err)
		}

		// 3. Admin stats
		stResp, stBody := doReq("GET", "/api/v1/admin/stats", nil, sessionCookie, "", "")
		if stResp.StatusCode != http.StatusOK {
			t.Fatalf("admin stats failed (%d): %v", stResp.StatusCode, stBody)
		}
		if stBody["total_users"] == nil {
			t.Fatalf("expected total_users in stats, got %v", stBody)
		}

		// 4. Admin list users
		uResp, uBody := doReq("GET", "/api/v1/admin/users", nil, sessionCookie, "", "")
		if uResp.StatusCode != http.StatusOK {
			t.Fatalf("admin list users failed (%d): %v", uResp.StatusCode, uBody)
		}
		usersList := uBody["items"].([]any)
		if len(usersList) == 0 {
			t.Fatal("expected at least 1 user in admin list")
		}

		// 5. Admin update user status (create a target user to suspend and reactivate)
		targetUser, _, err := st.CreateUser(ctx, fmt.Sprintf("target_%d@example.com", time.Now().UnixNano()), "Target User", "some-dummy-hash")
		if err != nil {
			t.Fatalf("create target user: %v", err)
		}

		mins := 60
		patchResp, patchBody := doReq("PATCH", "/api/v1/admin/users/"+targetUser.ID, map[string]any{
			"status":         "suspended",
			"locked_minutes": mins,
		}, sessionCookie, csrfToken, "")
		if patchResp.StatusCode != http.StatusOK {
			t.Fatalf("admin update user status failed (%d): %v", patchResp.StatusCode, patchBody)
		}

		// Re-activate target user
		reactResp, _ := doReq("PATCH", "/api/v1/admin/users/"+targetUser.ID, map[string]any{
			"status": "active",
		}, sessionCookie, csrfToken, "")
		if reactResp.StatusCode != http.StatusOK {
			t.Fatalf("reactivate user failed (%d)", reactResp.StatusCode)
		}

		// 6. Admin audit events list
		evResp, evBody := doReq("GET", "/api/v1/admin/audit/events", nil, sessionCookie, "", "")
		if evResp.StatusCode != http.StatusOK {
			t.Fatalf("admin list audit events failed (%d): %v", evResp.StatusCode, evBody)
		}
		events := evBody["items"].([]any)
		if len(events) == 0 {
			t.Fatal("expected audit events in admin list")
		}
		firstEv := events[0].(map[string]any)
		if firstEv["row_hash_hex"] == nil || firstEv["prev_hash_hex"] == nil {
			t.Fatalf("expected cryptographic hash chain fields in event, got %v", firstEv)
		}

		// 7. Verify hash chain integrity
		verResp, verBody := doReq("GET", "/api/v1/admin/audit/verify", nil, sessionCookie, "", "")
		if verResp.StatusCode != http.StatusOK {
			t.Fatalf("admin audit verify failed (%d): %v", verResp.StatusCode, verBody)
		}
		if verBody["intact"] != true {
			t.Fatalf("expected audit log chain to be intact, got %v", verBody)
		}
	})
}
