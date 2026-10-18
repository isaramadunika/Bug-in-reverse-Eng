package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tetraneurons/reversebug/api/internal/ai"
	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/config"
	"github.com/tetraneurons/reversebug/api/internal/db"
	"github.com/tetraneurons/reversebug/api/internal/mail"
	"github.com/tetraneurons/reversebug/api/internal/ratelimit"
	"github.com/tetraneurons/reversebug/api/internal/server"
	"github.com/tetraneurons/reversebug/api/internal/storage"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

func TestPhase4AIAgentAndCopilot(t *testing.T) {
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

	client := &http.Client{}

	// 1. Register & verify user
	email := fmt.Sprintf("phase4-ai-%d@reversebug.test", time.Now().UnixNano())
	regBody, _ := json.Marshal(map[string]any{
		"email":        email,
		"password":     "Str0ng!Phase4Pass#",
		"display_name": "Phase 4 AI Engineer",
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
	token := strings.Fields(tokenParts[1])[0]

	vBody, _ := json.Marshal(map[string]string{"token": token})
	_, _ = client.Post(ts.URL+"/api/v1/auth/verify-email", "application/json", bytes.NewReader(vBody))

	// 2. Login
	loginBody, _ := json.Marshal(map[string]string{"email": email, "password": "Str0ng!Phase4Pass#"})
	lRes, _ := client.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(loginBody))
	var sessionCookie *http.Cookie
	for _, c := range lRes.Cookies() {
		if c.Name == "rb_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie missing")
	}

	// 3. Get session CSRF
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/v1/auth/session", nil)
	req.AddCookie(sessionCookie)
	sRes, err := client.Do(req)
	if err != nil || sRes.StatusCode != http.StatusOK {
		t.Fatalf("get session failed: %v", err)
	}
	var sessData struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.NewDecoder(sRes.Body).Decode(&sessData)

	doAuthedReq := func(method, path string, body []byte) *http.Response {
		r, _ := http.NewRequestWithContext(ctx, method, ts.URL+path, bytes.NewReader(body))
		r.AddCookie(sessionCookie)
		r.Header.Set("X-CSRF-Token", sessData.CSRFToken)
		if len(body) > 0 {
			r.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		return resp
	}

	// 4. Create Project
	pBody, _ := json.Marshal(map[string]any{
		"name":              "AI Target Mobile App",
		"description":       "Phase 4 AI investigation testing",
		"package_name":      "com.reversebug.aitarget",
		"application_owner": "SecOps AI Team",
		"environment":       "staging",
		"tags":              []string{"ai", "mobile"},
	})
	pRes := doAuthedReq("POST", "/api/v1/projects", pBody)
	if pRes.StatusCode != http.StatusCreated {
		t.Fatalf("create project: %d", pRes.StatusCode)
	}
	var projResp struct {
		Project store.Project `json:"project"`
	}
	_ = json.NewDecoder(pRes.Body).Decode(&projResp)
	projectID := projResp.Project.ID

	// 5. Submit Attestation
	authBody, _ := json.Marshal(map[string]any{
		"basis":                     "client_contract",
		"scope_description":         "Authorized Phase 4 Security Investigation",
		"allows_dynamic_validation": true,
	})
	aRes := doAuthedReq("POST", fmt.Sprintf("/api/v1/projects/%s/authorizations", projectID), authBody)
	if aRes.StatusCode != http.StatusCreated {
		t.Fatalf("attestation creation: %d", aRes.StatusCode)
	}

	// 6. Upload APK
	apkBytes := createValidMockAPK()
	bodyBuf := new(bytes.Buffer)
	mpw := multipart.NewWriter(bodyBuf)
	part, _ := mpw.CreateFormFile("file", "ai-test.apk")
	_, _ = part.Write(apkBytes)
	_ = mpw.Close()

	upReq, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/projects/%s/artifacts/uploads", ts.URL, projectID), bodyBuf)
	upReq.AddCookie(sessionCookie)
	upReq.Header.Set("X-CSRF-Token", sessData.CSRFToken)
	upReq.Header.Set("Content-Type", mpw.FormDataContentType())
	upRes, err := client.Do(upReq)
	if err != nil || upRes.StatusCode != http.StatusCreated {
		t.Fatalf("upload apk failed: %d", upRes.StatusCode)
	}
	var upData struct {
		ArtifactVersion struct {
			ID string `json:"id"`
		} `json:"artifact_version"`
	}
	_ = json.NewDecoder(upRes.Body).Decode(&upData)
	artifactVersionID := upData.ArtifactVersion.ID

	// 7. Enqueue Scan
	scanReqBody, _ := json.Marshal(map[string]string{
		"artifact_version_id": artifactVersionID,
		"profile_id":          "standard",
	})
	scRes := doAuthedReq("POST", fmt.Sprintf("/api/v1/projects/%s/scans", projectID), scanReqBody)
	if scRes.StatusCode != http.StatusCreated {
		t.Fatalf("create scan: %d", scRes.StatusCode)
	}
	var scanData struct {
		Scan store.Scan `json:"scan"`
	}
	_ = json.NewDecoder(scRes.Body).Decode(&scanData)
	scanID := scanData.Scan.ID

	// 8. Insert Finding & Evidence for AI test
	var findingID string
	err = pool.QueryRow(ctx, `
		INSERT INTO findings (
			scan_id, fingerprint, rule_id, rule_version, title, description,
			severity, confidence, verification_status, reachability, category,
			cwe_ids, masvs_ids, impact, preconditions, remediation, review_status
		) VALUES (
			$1, 'fp_ai_exported_001', 'RB-COMP-001', '1.0.0',
			'Unprotected Exported Activity AuthActivity',
			'Activity com.reversebug.aitarget.AuthActivity is exported without permissions.',
			'high', 'high', 'static_evidence', 'reachable', 'manifest',
			ARRAY['CWE-926'], ARRAY['MASVS-PLATFORM-1'],
			'Allows arbitrary 3rd party apps to launch authentication flow and inject intents.',
			'Target installed on device.',
			'Set android:exported="false".',
			'open'
		) RETURNING id;
	`, scanID).Scan(&findingID)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	var evidenceID string
	err = pool.QueryRow(ctx, `
		INSERT INTO evidence (
			scan_id, finding_id, artifact_sha256, evidence_type, location,
			line_start, line_end, excerpt, analysis_source, tool_name, tool_version, confidence
		) VALUES (
			$1, $2, 'mocksha256', 'manifest_element', 'AndroidManifest.xml',
			14, 20, '<activity android:name=".AuthActivity" android:exported="true" />',
			'static_rules', 'reversebug-rules', '1.0.0', 'high'
		) RETURNING id;
	`, scanID, findingID).Scan(&evidenceID)
	if err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	// Insert graph nodes
	var node1ID, node2ID string
	_ = pool.QueryRow(ctx, `
		INSERT INTO evidence_nodes (scan_id, node_key, node_type, label, severity, properties)
		VALUES ($1, 'apk:root', 'apk', 'ai-test.apk', 'info', '{}'::jsonb)
		RETURNING id;
	`, scanID).Scan(&node1ID)

	_ = pool.QueryRow(ctx, `
		INSERT INTO evidence_nodes (scan_id, node_key, node_type, label, severity, properties)
		VALUES ($1, 'comp:AuthActivity', 'entry_point', 'AuthActivity', 'high', '{"exported": true}'::jsonb)
		RETURNING id;
	`, scanID).Scan(&node2ID)

	_, _ = pool.Exec(ctx, `
		INSERT INTO evidence_edges (scan_id, source_id, target_id, edge_type, relation_status, provenance)
		VALUES ($1, $2, $3, 'DECLARES', 'observed', '{}'::jsonb);
	`, scanID, node1ID, node2ID)

	// Update scan score
	_, _ = pool.Exec(ctx, `
		UPDATE scans
		SET status = 'completed',
		    security_score = 85
		WHERE id = $1;
	`, scanID)

	// -------------------------------------------------------------------------
	// TEST 1: Execute AI Investigation Agent
	// -------------------------------------------------------------------------
	investigateReqBody, _ := json.Marshal(map[string]string{
		"agent": "validation_analyst",
	})
	invRes := doAuthedReq("POST", fmt.Sprintf("/api/v1/scans/%s/findings/%s/analyses", scanID, findingID), investigateReqBody)
	if invRes.StatusCode != http.StatusOK {
		t.Fatalf("investigate finding failed: %d", invRes.StatusCode)
	}
	var invData struct {
		Investigation ai.AgentExecutionResult `json:"investigation"`
	}
	_ = json.NewDecoder(invRes.Body).Decode(&invData)

	if invData.Investigation.Status != "succeeded" {
		t.Fatalf("expected investigation status 'succeeded', got %s", invData.Investigation.Status)
	}
	if invData.Investigation.Analysis.Verdict != "confirmed" {
		t.Fatalf("expected verdict 'confirmed', got %s", invData.Investigation.Analysis.Verdict)
	}
	if len(invData.Investigation.CitedEvidenceIDs) == 0 {
		t.Fatal("expected cited evidence IDs from investigation")
	}
	if invData.Investigation.ToolCalls < 2 {
		t.Fatalf("expected at least 2 tool calls, got %d", invData.Investigation.ToolCalls)
	}
	if invData.Investigation.CostUSDMicros <= 0 {
		t.Fatalf("expected cost tracking, got %d", invData.Investigation.CostUSDMicros)
	}

	// -------------------------------------------------------------------------
	// TEST 2: List Analyses for Finding
	// -------------------------------------------------------------------------
	listAnalysesRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/scans/%s/findings/%s/analyses", scanID, findingID), nil)
	if listAnalysesRes.StatusCode != http.StatusOK {
		t.Fatalf("list analyses: %d", listAnalysesRes.StatusCode)
	}
	var listAnalysesData struct {
		Analyses []store.AIAnalysis `json:"analyses"`
		Count    int                `json:"count"`
	}
	_ = json.NewDecoder(listAnalysesRes.Body).Decode(&listAnalysesData)
	if listAnalysesData.Count != 1 || len(listAnalysesData.Analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", listAnalysesData.Count)
	}
	analysisID := listAnalysesData.Analyses[0].ID

	// -------------------------------------------------------------------------
	// TEST 3: Get Analysis Detail with Resolved Cited Evidence
	// -------------------------------------------------------------------------
	getAnalysisRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/analyses/%s", analysisID), nil)
	if getAnalysisRes.StatusCode != http.StatusOK {
		t.Fatalf("get analysis: %d", getAnalysisRes.StatusCode)
	}
	var getAnalysisData struct {
		Analysis store.AIAnalysis `json:"analysis"`
	}
	_ = json.NewDecoder(getAnalysisRes.Body).Decode(&getAnalysisData)
	if len(getAnalysisData.Analysis.CitedEvidence) == 0 {
		t.Fatal("expected cited evidence items resolved in analysis response")
	}
	if getAnalysisData.Analysis.CitedEvidence[0].ID != evidenceID {
		t.Fatalf("expected cited evidence ID %s, got %s", evidenceID, getAnalysisData.Analysis.CitedEvidence[0].ID)
	}

	// -------------------------------------------------------------------------
	// TEST 4: Ask Security Copilot
	// -------------------------------------------------------------------------
	copilotReqBody, _ := json.Marshal(map[string]string{
		"question": "Can an external app launch AuthActivity and how do we remediate it?",
	})
	copilotRes := doAuthedReq("POST", fmt.Sprintf("/api/v1/scans/%s/ask", scanID), copilotReqBody)
	if copilotRes.StatusCode != http.StatusOK {
		t.Fatalf("copilot ask failed: %d", copilotRes.StatusCode)
	}
	var copilotData ai.CopilotAnswerResponse
	_ = json.NewDecoder(copilotRes.Body).Decode(&copilotData)

	if !strings.Contains(copilotData.Answer, "Security Score") {
		t.Fatalf("copilot answer missing scan score grounding: %s", copilotData.Answer)
	}
	if len(copilotData.CitedFindingIDs) == 0 {
		t.Fatal("expected cited finding IDs in copilot answer")
	}
	if len(copilotData.SuggestedFixes) == 0 {
		t.Fatal("expected suggested fixes in copilot answer")
	}
}
