package server_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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

func createValidMockAPK() []byte {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	// AndroidManifest.xml
	mw, _ := zw.Create("AndroidManifest.xml")
	// Minimal binary XML mock
	_, _ = mw.Write([]byte{0x03, 0x00, 0x08, 0x00, 0x24, 0x00, 0x00, 0x00})

	// classes.dex
	dw, _ := zw.Create("classes.dex")
	_, _ = dw.Write([]byte("dex\n035\x00mock_bytecode"))

	// resources.arsc
	rw, _ := zw.Create("resources.arsc")
	_, _ = rw.Write([]byte{0x02, 0x00, 0x0c, 0x00})

	_ = zw.Close()
	return buf.Bytes()
}

func createZipSlipAPK() []byte {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	mw, _ := zw.Create("../../etc/passwd")
	_, _ = mw.Write([]byte("root:x:0:0::/root:/bin/bash"))

	_ = zw.Close()
	return buf.Bytes()
}

func TestPhase2Lifecycle(t *testing.T) {
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
		t.Fatalf("server.New: %v", err)
	}

	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	client := &http.Client{
		Jar: nil, // We handle cookies manually to verify CSRF and session handling
	}

	// 1. Register and verify user
	email := fmt.Sprintf("secops-%d@enterprise-corp.io", time.Now().UnixNano())
	regBody, _ := json.Marshal(map[string]any{
		"email":        email,
		"password":     "Str0ng!P@ssw0rd99",
		"display_name": "SecOps Lead",
		"accept_terms": true,
	})
	res, err := client.Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(regBody))
	if err != nil || res.StatusCode != http.StatusAccepted {
		t.Fatalf("register: code %d, err %v", res.StatusCode, err)
	}

	lastMsg, ok := mailer.Last()
	if !ok {
		t.Fatal("expected verification email")
	}
	tokenParts := strings.Split(lastMsg.Text, "token=")
	if len(tokenParts) < 2 {
		t.Fatalf("token= not found in email text: %s", lastMsg.Text)
	}
	token := strings.Fields(tokenParts[1])[0]
	if token == "" {
		t.Fatal("verification token not extracted")
	}

	vBody, _ := json.Marshal(map[string]string{"token": token})
	vRes, _ := client.Post(ts.URL+"/api/v1/auth/verify-email", "application/json", bytes.NewReader(vBody))
	if vRes.StatusCode != http.StatusOK {
		t.Fatalf("verify-email failed: %d", vRes.StatusCode)
	}

	// 2. Login
	loginBody, _ := json.Marshal(map[string]string{"email": email, "password": "Str0ng!P@ssw0rd99"})
	lRes, _ := client.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(loginBody))
	if lRes.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", lRes.StatusCode)
	}
	var sessionCookie *http.Cookie
	for _, c := range lRes.Cookies() {
		if c.Name == "rb_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("missing session cookie")
	}

	var sessionObj struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.NewDecoder(lRes.Body).Decode(&sessionObj)
	csrf := sessionObj.CSRFToken

	// Helper for authenticated requests
	authReq := func(method, path string, body io.Reader, contentType string) *http.Request {
		req, _ := http.NewRequest(method, ts.URL+path, body)
		req.AddCookie(sessionCookie)
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Origin", "http://localhost:5173")
		return req
	}

	// 3. Create Project
	projBody, _ := json.Marshal(map[string]any{
		"name":              "FinTech Mobile Banking",
		"description":       "Core banking Android client for penetration testing",
		"application_owner": "FinTech Corp Security",
		"environment":       "production",
		"tags":              []string{"finance", "pci-dss", "critical"},
	})
	pReq := authReq(http.MethodPost, "/api/v1/projects", bytes.NewReader(projBody), "application/json")
	pRes, err := client.Do(pReq)
	if err != nil || pRes.StatusCode != http.StatusCreated {
		t.Fatalf("create project: code %d, err %v", pRes.StatusCode, err)
	}

	var projResp struct {
		Project struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"project"`
	}
	_ = json.NewDecoder(pRes.Body).Decode(&projResp)
	projectID := projResp.Project.ID
	if projectID == "" {
		t.Fatal("empty project ID")
	}

	// 4. Test upload zip-slip defense (must reject with 400)
	{
		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "malicious.apk")
		_, _ = part.Write(createZipSlipAPK())
		_ = writer.Close()

		slipReq := authReq(http.MethodPost, "/api/v1/projects/"+projectID+"/artifacts/uploads", body, writer.FormDataContentType())
		slipRes, _ := client.Do(slipReq)
		if slipRes.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for zip-slip, got %d", slipRes.StatusCode)
		}
	}

	// 5. Test valid APK upload
	var artifactVersionID string
	{
		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "app-release.apk")
		_, _ = part.Write(createValidMockAPK())
		_ = writer.Close()

		upReq := authReq(http.MethodPost, "/api/v1/projects/"+projectID+"/artifacts/uploads", body, writer.FormDataContentType())
		upRes, err := client.Do(upReq)
		if err != nil || upRes.StatusCode != http.StatusCreated {
			t.Fatalf("upload valid APK failed: code %d, err %v", upRes.StatusCode, err)
		}

		var upResp struct {
			ArtifactVersion struct {
				ID string `json:"id"`
			} `json:"artifact_version"`
			SHA256 string `json:"sha256"`
		}
		_ = json.NewDecoder(upRes.Body).Decode(&upResp)
		artifactVersionID = upResp.ArtifactVersion.ID
		if artifactVersionID == "" {
			t.Fatal("empty artifact version id")
		}
	}

	// 6. Test scan creation without authorization record (must be rejected)
	{
		scanBody, _ := json.Marshal(map[string]any{
			"artifact_version_id": artifactVersionID,
			"profile_id":          "standard",
		})
		sReq := authReq(http.MethodPost, "/api/v1/projects/"+projectID+"/scans", bytes.NewReader(scanBody), "application/json")
		sRes, _ := client.Do(sReq)
		if sRes.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for scan without authorization, got %d", sRes.StatusCode)
		}
	}

	// 7. Record Attestation of Authorization
	{
		authBody, _ := json.Marshal(map[string]any{
			"basis":                     "client_contract",
			"scope_description":         "Authorized penetration test under MSA Contract #SEC-2026-9812",
			"allows_dynamic_validation": false,
		})
		aReq := authReq(http.MethodPost, "/api/v1/projects/"+projectID+"/authorizations", bytes.NewReader(authBody), "application/json")
		aRes, err := client.Do(aReq)
		if err != nil || aRes.StatusCode != http.StatusCreated {
			t.Fatalf("create authorization: code %d, err %v", aRes.StatusCode, err)
		}
	}

	// 8. Now enqueue scan (must succeed)
	var scanID string
	{
		scanBody, _ := json.Marshal(map[string]any{
			"artifact_version_id": artifactVersionID,
			"profile_id":          "standard",
		})
		sReq := authReq(http.MethodPost, "/api/v1/projects/"+projectID+"/scans", bytes.NewReader(scanBody), "application/json")
		sRes, err := client.Do(sReq)
		if err != nil || sRes.StatusCode != http.StatusCreated {
			t.Fatalf("enqueue scan failed: code %d, err %v", sRes.StatusCode, err)
		}

		var scanResp struct {
			Scan struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"scan"`
		}
		_ = json.NewDecoder(sRes.Body).Decode(&scanResp)
		scanID = scanResp.Scan.ID
		if scanID == "" {
			t.Fatal("empty scan ID")
		}
		if scanResp.Scan.Status != "queued" {
			t.Fatalf("expected queued status, got %s", scanResp.Scan.Status)
		}
	}

	// 9. Inspect scan
	{
		gReq := authReq(http.MethodGet, "/api/v1/scans/"+scanID, nil, "")
		gRes, err := client.Do(gReq)
		if err != nil || gRes.StatusCode != http.StatusOK {
			t.Fatalf("get scan: code %d, err %v", gRes.StatusCode, err)
		}

		var detailResp struct {
			Scan struct {
				ID     string `json:"id"`
				Stages []any  `json:"stages"`
			} `json:"scan"`
		}
		_ = json.NewDecoder(gRes.Body).Decode(&detailResp)
		if len(detailResp.Scan.Stages) == 0 {
			t.Fatal("expected initial queued stage event")
		}
	}

	// 10. Cancel scan
	{
		cReq := authReq(http.MethodPost, "/api/v1/scans/"+scanID+"/cancel", nil, "")
		cRes, err := client.Do(cReq)
		if err != nil || cRes.StatusCode != http.StatusOK {
			t.Fatalf("cancel scan: code %d, err %v", cRes.StatusCode, err)
		}
	}

	// 11. Test SSRF protection on URL import
	{
		ssrfBody, _ := json.Marshal(map[string]string{
			"url": "http://169.254.169.254/latest/meta-data/",
		})
		ssrfReq := authReq(http.MethodPost, "/api/v1/projects/"+projectID+"/artifacts/import-url", bytes.NewReader(ssrfBody), "application/json")
		ssrfRes, _ := client.Do(ssrfReq)
		if ssrfRes.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected SSRF attempt to 169.254.169.254 to be rejected with 400, got %d", ssrfRes.StatusCode)
		}
	}
}
