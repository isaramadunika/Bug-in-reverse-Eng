package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/auth"
	"github.com/tetraneurons/reversebug/api/internal/config"
	"github.com/tetraneurons/reversebug/api/internal/db"
	"github.com/tetraneurons/reversebug/api/internal/mail"
	"github.com/tetraneurons/reversebug/api/internal/ratelimit"
	"github.com/tetraneurons/reversebug/api/internal/server"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

const testDBURL = "postgres://reversebug:reversebug_dev_password@127.0.0.1:5433/reversebug?sslmode=disable"

var fastArgon = auth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

type testEnv struct {
	server  *server.Server
	handler http.Handler
	store   *store.Store
	audit   *audit.Logger
	mailer  *mail.Recorder
	limiter ratelimit.Limiter
	cfg     *config.Config
}

func setupTestEnv(t *testing.T) *testEnv {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, testDBURL)
	if err != nil {
		t.Skipf("skipping integration tests, postgres not available: %v", err)
	}

	cfg := &config.Config{
		Env:                    "development",
		HTTPAddr:               ":8080",
		DatabaseURL:            testDBURL,
		PublicBaseURL:          "http://localhost:5173",
		AllowedOrigins:         []string{"http://localhost:5173"},
		CookieSecure:           false,
		SessionIdleTimeout:     1 * time.Hour,
		SessionAbsoluteTimeout: 24 * time.Hour,
		DataEncryptionKey:      []byte("0123456789abcdef0123456789abcdef"),
		APIKeyPepper:           []byte("0123456789abcdef0123456789abcdef"),
	}

	st := store.New(pool)
	auditLogger := audit.New(pool)
	rec := &mail.Recorder{}
	limiter := ratelimit.NewMemory()

	srv, err := server.New(server.Deps{
		Config:   cfg,
		Store:    st,
		Audit:    auditLogger,
		Mailer:   rec,
		Limiter:  limiter,
		Argon:    &fastArgon,
		SyncMail: true,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return &testEnv{
		server:  srv,
		handler: srv.Routes(),
		store:   st,
		audit:   auditLogger,
		mailer:  rec,
		limiter: limiter,
		cfg:     cfg,
	}
}

func extractCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestFullAuthLifecycle(t *testing.T) {
	env := setupTestEnv(t)

	testEmail := "analyst." + time.Now().Format("150405.000000") + "@example.com"
	testPassword := "Correct-Horse-Battery-Staple-2026!"

	// 1. Register
	regBody, _ := json.Marshal(map[string]any{
		"email":        testEmail,
		"display_name": "Senior Security Analyst",
		"password":     testPassword,
		"accept_terms": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on register, got %d: %s", w.Code, w.Body.String())
	}

	// Verify verification email was recorded
	lastMsg, ok := env.mailer.Last()
	if !ok || !strings.Contains(lastMsg.Subject, "Verify your ReverseBug") {
		t.Fatalf("verification email not sent")
	}

	// Extract verification token from email text
	tokenURL := strings.Split(lastMsg.Text, "token=")[1]
	token := strings.Fields(tokenURL)[0]

	// 2. Verify Email
	verifyBody, _ := json.Marshal(map[string]string{"token": token})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email", bytes.NewReader(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on verify-email, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Login
	loginBody, _ := json.Marshal(map[string]string{
		"email":    testEmail,
		"password": testPassword,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on login, got %d: %s", w.Code, w.Body.String())
	}

	sessionCookie := extractCookie(w.Result(), "rb_session")
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatalf("expected session cookie to be set")
	}

	var loginResp struct {
		Authenticated bool   `json:"authenticated"`
		CSRFToken     string `json:"csrf_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &loginResp)
	if !loginResp.Authenticated || loginResp.CSRFToken == "" {
		t.Fatalf("expected authenticated=true with CSRF token, got %+v", loginResp)
	}

	// 4. Test CSRF Protection on protected mutation
	// Request without CSRF token must fail (403 CSRF failed)
	onboardingBody, _ := json.Marshal(map[string]any{"step": 3, "completed": false})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/me/onboarding", bytes.NewReader(onboardingBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden without CSRF token, got %d", w.Code)
	}

	// Request WITH valid CSRF token must succeed (204 No Content)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/me/onboarding", bytes.NewReader(onboardingBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content with valid CSRF token, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Query /api/v1/me to verify persisted onboarding progress
	req = httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /me, got %d", w.Code)
	}
	var meResp struct {
		Email          string `json:"email"`
		OnboardingStep int    `json:"onboarding_step"`
		EmailVerified  bool   `json:"email_verified"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &meResp)
	if meResp.OnboardingStep != 3 || !meResp.EmailVerified {
		t.Fatalf("unexpected /me response: %+v", meResp)
	}

	// 6. Test Dashboard query
	req = httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary?days=30", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on dashboard summary, got %d: %s", w.Code, w.Body.String())
	}

	// 7. Test Logout
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("X-CSRF-Token", loginResp.CSRFToken)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on logout, got %d", w.Code)
	}

	// Session is now revoked; calling /me must return 401 Unauthorized
	req = httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on revoked session, got %d", w.Code)
	}
}

func TestPublicPlansEndpoint(t *testing.T) {
	env := setupTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/plans", nil)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on public plans, got %d", w.Code)
	}

	var resp struct {
		Items []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			PriceCents int    `json:"price_cents"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode plans response: %v", err)
	}

	if len(resp.Items) < 4 {
		t.Fatalf("expected at least 4 plans (free, pro, researcher, team), got %d", len(resp.Items))
	}
}
