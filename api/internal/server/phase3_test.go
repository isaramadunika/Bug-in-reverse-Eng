package server_test

import (
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

func TestPhase3FindingsGraphReports(t *testing.T) {
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
	email := fmt.Sprintf("phase3-sec-%d@reversebug.test", time.Now().UnixNano())
	regBody, _ := json.Marshal(map[string]any{
		"email":        email,
		"password":     "Str0ng!Phase3Pass#",
		"display_name": "Phase 3 Engineer",
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
	loginBody, _ := json.Marshal(map[string]string{"email": email, "password": "Str0ng!Phase3Pass#"})
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

	// 3. Get session to fetch CSRF token
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/v1/auth/session", nil)
	req.AddCookie(sessionCookie)
	sRes, err := client.Do(req)
	if err != nil || sRes.StatusCode != http.StatusOK {
		t.Fatalf("get session failed: %v", err)
	}
	var sessData struct {
		CSRFToken string `json:"csrf_token"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
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
		"name":              "Vulnerable Banking Demo",
		"description":       "Phase 3 E2E test project",
		"package_name":      "com.reversebug.vulnerableapp",
		"application_owner": "SecOps Team",
		"environment":       "production",
		"tags":              []string{"android", "finance", "phase3"},
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

	// 5. Submit Attestation of Authorization
	authBody, _ := json.Marshal(map[string]any{
		"basis":                     "client_contract",
		"scope_description":         "Authorized Phase 3 Security Audit under MSA Contract",
		"allows_dynamic_validation": false,
	})
	aRes := doAuthedReq("POST", fmt.Sprintf("/api/v1/projects/%s/authorizations", projectID), authBody)
	if aRes.StatusCode != http.StatusCreated {
		t.Fatalf("attestation creation failed: %d", aRes.StatusCode)
	}

	// 6. Upload APK
	apkBytes := createValidMockAPK()
	bodyBuf := new(bytes.Buffer)
	mpw := multipart.NewWriter(bodyBuf)
	part, _ := mpw.CreateFormFile("file", "vulnerable-app.apk")
	_, _ = part.Write(apkBytes)
	_ = mpw.Close()

	upReq, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/projects/%s/artifacts/uploads", ts.URL, projectID), bodyBuf)
	upReq.AddCookie(sessionCookie)
	upReq.Header.Set("X-CSRF-Token", sessData.CSRFToken)
	upReq.Header.Set("Content-Type", mpw.FormDataContentType())
	upRes, err := client.Do(upReq)
	if err != nil || upRes.StatusCode != http.StatusCreated {
		t.Fatalf("upload apk failed: code %d, err %v", upRes.StatusCode, err)
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

	// 8. Insert static findings, evidence, occurrences, and evidence graph into DB
	var findingID string
	err = pool.QueryRow(ctx, `
		INSERT INTO findings (
			scan_id, fingerprint, rule_id, rule_version, title, description,
			severity, confidence, verification_status, reachability, category,
			cwe_ids, masvs_ids, impact, preconditions, remediation, review_status
		) VALUES (
			$1, 'fp_test_exported_activity_001', 'RB-COMP-001', '1.0.0',
			'Unprotected Exported Activity Disclosed',
			'Activity com.reversebug.vulnerableapp.AuthActivity is exported without android:permission.',
			'high', 'high', 'static_evidence', 'reachable', 'manifest',
			ARRAY['CWE-926'], ARRAY['MASVS-PLATFORM-1'],
			'Any application on the device can launch this activity and hijack authorization flow.',
			'Target application must be installed on the device.',
			'Set android:exported="false" or declare android:permission attribute.',
			'open'
		) RETURNING id;
	`, scanID).Scan(&findingID)
	if err != nil {
		t.Fatalf("insert test finding: %v", err)
	}

	// Insert occurrence
	_, err = pool.Exec(ctx, `
		INSERT INTO finding_occurrences (
			finding_id, file_path, line_start, line_end, component_name
		) VALUES ($1, 'AndroidManifest.xml', 14, 22, 'com.reversebug.vulnerableapp.AuthActivity');
	`, findingID)
	if err != nil {
		t.Fatalf("insert test occurrence: %v", err)
	}

	// Insert evidence
	_, err = pool.Exec(ctx, `
		INSERT INTO evidence (
			scan_id, finding_id, artifact_sha256, evidence_type, location,
			line_start, line_end, excerpt, analysis_source, tool_name, tool_version, confidence
		) VALUES (
			$1, $2, 'mocksha256', 'manifest_element', 'AndroidManifest.xml',
			14, 22, '<activity android:name=".AuthActivity" android:exported="true" />',
			'static_rules', 'reversebug-rules', '1.0.0', 'high'
		);
	`, scanID, findingID)
	if err != nil {
		t.Fatalf("insert test evidence: %v", err)
	}

	// Insert graph nodes
	var node1ID, node2ID string
	_ = pool.QueryRow(ctx, `
		INSERT INTO evidence_nodes (scan_id, node_key, node_type, label, severity, properties)
		VALUES ($1, 'apk:root', 'apk', 'vulnerable-app.apk', 'info', '{}'::jsonb)
		RETURNING id;
	`, scanID).Scan(&node1ID)

	_ = pool.QueryRow(ctx, `
		INSERT INTO evidence_nodes (scan_id, node_key, node_type, label, severity, properties)
		VALUES ($1, 'comp:AuthActivity', 'component', 'AuthActivity', 'high', '{"exported": true}'::jsonb)
		RETURNING id;
	`, scanID).Scan(&node2ID)

	// Insert graph edge
	_, _ = pool.Exec(ctx, `
		INSERT INTO evidence_edges (scan_id, source_id, target_id, edge_type, relation_status, provenance)
		VALUES ($1, $2, $3, 'DECLARES', 'observed', '{}'::jsonb);
	`, scanID, node1ID, node2ID)

	// Update scan score and status to completed
	_, _ = pool.Exec(ctx, `
		UPDATE scans
		SET status = 'completed',
		    security_score = 85,
		    score_state = 'valid',
		    score_version = 'scoring_v1',
		    score_breakdown = '{"base_score": 100, "final_score": 85, "deductions": [{"rule": "RB-COMP-001", "points": 15}]}'::jsonb
		WHERE id = $1;
	`, scanID)

	// -------------------------------------------------------------------------
	// TEST 1: List Findings
	// -------------------------------------------------------------------------
	fListRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/scans/%s/findings", scanID), nil)
	if fListRes.StatusCode != http.StatusOK {
		t.Fatalf("list findings: %d", fListRes.StatusCode)
	}
	var fListData struct {
		Findings []store.Finding `json:"findings"`
		Count    int             `json:"count"`
	}
	_ = json.NewDecoder(fListRes.Body).Decode(&fListData)
	if fListData.Count != 1 || len(fListData.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", fListData.Count)
	}
	if fListData.Findings[0].RuleID != "RB-COMP-001" {
		t.Fatalf("expected rule RB-COMP-001, got %s", fListData.Findings[0].RuleID)
	}

	// -------------------------------------------------------------------------
	// TEST 2: Get Specific Finding with Occurrences & Evidence
	// -------------------------------------------------------------------------
	fGetRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/findings/%s", findingID), nil)
	if fGetRes.StatusCode != http.StatusOK {
		t.Fatalf("get finding: %d", fGetRes.StatusCode)
	}
	var fGetData struct {
		Finding store.Finding `json:"finding"`
	}
	_ = json.NewDecoder(fGetRes.Body).Decode(&fGetData)
	if len(fGetData.Finding.Occurrences) != 1 {
		t.Fatalf("expected 1 occurrence, got %d", len(fGetData.Finding.Occurrences))
	}
	if len(fGetData.Finding.Evidence) != 1 {
		t.Fatalf("expected 1 evidence item, got %d", len(fGetData.Finding.Evidence))
	}

	// -------------------------------------------------------------------------
	// TEST 3: Update Finding Triage Review Status
	// -------------------------------------------------------------------------
	triageBody, _ := json.Marshal(map[string]any{
		"review_status": "confirmed",
	})
	fPatchRes := doAuthedReq("PATCH", fmt.Sprintf("/api/v1/findings/%s", findingID), triageBody)
	if fPatchRes.StatusCode != http.StatusOK {
		t.Fatalf("patch finding triage status: %d", fPatchRes.StatusCode)
	}
	var fPatchData struct {
		Finding store.Finding `json:"finding"`
	}
	_ = json.NewDecoder(fPatchRes.Body).Decode(&fPatchData)
	if fPatchData.Finding.ReviewStatus != "confirmed" {
		t.Fatalf("expected review_status 'confirmed', got %s", fPatchData.Finding.ReviewStatus)
	}

	// -------------------------------------------------------------------------
	// TEST 4: Get Evidence Graph
	// -------------------------------------------------------------------------
	graphRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/scans/%s/evidence-graph", scanID), nil)
	if graphRes.StatusCode != http.StatusOK {
		t.Fatalf("get evidence graph: %d", graphRes.StatusCode)
	}
	var graphData store.EvidenceGraph
	_ = json.NewDecoder(graphRes.Body).Decode(&graphData)
	if len(graphData.Nodes) != 2 {
		t.Fatalf("expected 2 graph nodes, got %d", len(graphData.Nodes))
	}
	if len(graphData.Edges) != 1 {
		t.Fatalf("expected 1 graph edge, got %d", len(graphData.Edges))
	}
	if graphData.Edges[0].EdgeType != "DECLARES" {
		t.Fatalf("expected DECLARES edge type, got %s", graphData.Edges[0].EdgeType)
	}

	// -------------------------------------------------------------------------
	// TEST 5: Source File Inspector
	// -------------------------------------------------------------------------
	srcRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/scans/%s/source-file?path=AndroidManifest.xml", scanID), nil)
	if srcRes.StatusCode != http.StatusOK {
		t.Fatalf("get source file: %d", srcRes.StatusCode)
	}
	var srcData server.SourceFileResp
	_ = json.NewDecoder(srcRes.Body).Decode(&srcData)
	if srcData.Path != "AndroidManifest.xml" {
		t.Fatalf("expected AndroidManifest.xml path, got %s", srcData.Path)
	}
	if len(srcData.ArchiveFiles) == 0 {
		t.Fatal("expected archive files list in response")
	}

	// -------------------------------------------------------------------------
	// TEST 6: Report Generation (JSON format)
	// -------------------------------------------------------------------------
	repJsonBody, _ := json.Marshal(map[string]string{"format": "json"})
	repJsonRes := doAuthedReq("POST", fmt.Sprintf("/api/v1/scans/%s/reports", scanID), repJsonBody)
	if repJsonRes.StatusCode != http.StatusCreated {
		t.Fatalf("create json report: %d", repJsonRes.StatusCode)
	}
	var repJsonData struct {
		Report store.Report `json:"report"`
	}
	_ = json.NewDecoder(repJsonRes.Body).Decode(&repJsonData)
	if repJsonData.Report.Status != "ready" {
		t.Fatalf("expected ready status, got %s", repJsonData.Report.Status)
	}
	jsonReportID := repJsonData.Report.ID

	// Download JSON Report
	dlJsonRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/reports/%s/download", jsonReportID), nil)
	if dlJsonRes.StatusCode != http.StatusOK {
		t.Fatalf("download json report: %d", dlJsonRes.StatusCode)
	}
	dlJsonBytes, _ := io.ReadAll(dlJsonRes.Body)
	var downloadedReport map[string]any
	if err := json.Unmarshal(dlJsonBytes, &downloadedReport); err != nil {
		t.Fatalf("downloaded report invalid JSON: %v", err)
	}
	if downloadedReport["project_name"] != "Vulnerable Banking Demo" {
		t.Fatalf("expected Vulnerable Banking Demo in report, got %v", downloadedReport["project_name"])
	}

	// -------------------------------------------------------------------------
	// TEST 7: Report Generation (PDF/HTML format)
	// -------------------------------------------------------------------------
	repHtmlBody, _ := json.Marshal(map[string]string{"format": "pdf"})
	repHtmlRes := doAuthedReq("POST", fmt.Sprintf("/api/v1/scans/%s/reports", scanID), repHtmlBody)
	if repHtmlRes.StatusCode != http.StatusCreated {
		t.Fatalf("create pdf report: %d", repHtmlRes.StatusCode)
	}
	var repHtmlData struct {
		Report store.Report `json:"report"`
	}
	_ = json.NewDecoder(repHtmlRes.Body).Decode(&repHtmlData)
	htmlReportID := repHtmlData.Report.ID

	// Download HTML/PDF Report
	dlHtmlRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/reports/%s/download", htmlReportID), nil)
	if dlHtmlRes.StatusCode != http.StatusOK {
		t.Fatalf("download html/pdf report: %d", dlHtmlRes.StatusCode)
	}
	dlHtmlBytes, _ := io.ReadAll(dlHtmlRes.Body)
	if !strings.Contains(string(dlHtmlBytes), "REVERSEBUG") || !strings.Contains(string(dlHtmlBytes), "Vulnerable Banking Demo") {
		t.Fatalf("expected HTML report branding and title, got %s", string(dlHtmlBytes))
	}

	// -------------------------------------------------------------------------
	// TEST 8: List Reports for Scan
	// -------------------------------------------------------------------------
	listRepRes := doAuthedReq("GET", fmt.Sprintf("/api/v1/scans/%s/reports", scanID), nil)
	if listRepRes.StatusCode != http.StatusOK {
		t.Fatalf("list reports: %d", listRepRes.StatusCode)
	}
	var listRepData struct {
		Reports []store.Report `json:"reports"`
	}
	_ = json.NewDecoder(listRepRes.Body).Decode(&listRepData)
	if len(listRepData.Reports) < 2 {
		t.Fatalf("expected at least 2 reports, got %d", len(listRepData.Reports))
	}
}
