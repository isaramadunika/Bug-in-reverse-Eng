package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	"github.com/tetraneurons/reversebug/api/internal/report"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

type createReportReq struct {
	Format string `json:"format"` // "json" or "pdf"
}

func (s *Server) createReport(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	scanID := chi.URLParam(r, "scanID")
	if scanID == "" {
		return httpx.ErrNotFound
	}

	var req createReportReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		req.Format = "json"
	}
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))
	if req.Format != "json" && req.Format != "pdf" {
		req.Format = "json"
	}

	// 1. Fetch scan
	scan, err := s.store.GetScan(r.Context(), orgID, scanID)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	// 2. Fetch project
	project, err := s.store.GetProject(r.Context(), orgID, scan.ProjectID)
	if err != nil {
		return err
	}

	// 3. Fetch findings
	findings, err := s.store.ListFindings(r.Context(), orgID, scanID, store.FindingFilter{})
	if err != nil {
		return err
	}

	// Enrich findings with occurrences and evidence for report completeness
	for i := range findings {
		detailed, err := s.store.GetFinding(r.Context(), orgID, findings[i].ID)
		if err == nil && detailed != nil {
			findings[i].Occurrences = detailed.Occurrences
			findings[i].Evidence = detailed.Evidence
		}
	}

	// 4. Fetch authorization record (if any)
	authRecords, _ := s.store.ListAuthorizationRecords(r.Context(), orgID, scan.ProjectID)
	var activeAuth *store.AuthorizationRecord
	if len(authRecords) > 0 {
		activeAuth = &authRecords[0]
	}

	// 5. Create report record in store
	rep := &store.Report{
		ScanID:      scanID,
		Format:      req.Format,
		Status:      "generating",
		RequestedBy: &u.ID,
		IsSample:    false,
	}
	if err := s.store.CreateReport(r.Context(), rep); err != nil {
		return fmt.Errorf("create report record: %w", err)
	}

	// 6. Fetch artifact SHA256
	_, _, artifactSHA, err := s.store.GetScanArtifactStorageKey(r.Context(), orgID, scanID)
	if err != nil {
		artifactSHA = "unknown"
	}

	reportData := report.BuildReportData(
		rep.ID,
		&project.Project,
		&scan.Scan,
		findings,
		activeAuth,
		artifactSHA,
	)

	var payloadBytes []byte
	var ext string
	if req.Format == "pdf" {
		payloadBytes, err = report.GenerateHTML(reportData)
		ext = "html"
	} else {
		payloadBytes, err = report.GenerateJSON(reportData)
		ext = "json"
	}
	if err != nil {
		errMsg := err.Error()
		_ = s.store.UpdateReportStatus(r.Context(), rep.ID, "failed", nil, nil, nil, &errMsg)
		return fmt.Errorf("generate report payload: %w", err)
	}

	storageKey := fmt.Sprintf("reports/%s.%s", rep.ID, ext)
	sizeBytes, err := s.storage.Put(r.Context(), storageKey, bytes.NewReader(payloadBytes))
	if err != nil {
		errMsg := err.Error()
		_ = s.store.UpdateReportStatus(r.Context(), rep.ID, "failed", nil, nil, nil, &errMsg)
		return fmt.Errorf("save report artifact: %w", err)
	}

	shaDigest := store.ComputeSHA256(payloadBytes)
	if err := s.store.UpdateReportStatus(r.Context(), rep.ID, "ready", &storageKey, &shaDigest, &sizeBytes, nil); err != nil {
		return fmt.Errorf("finalize report status: %w", err)
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "report.generated",
		TargetType:  "report",
		TargetID:    rep.ID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata: map[string]any{
			"scan_id": scanID,
			"format":  req.Format,
			"size":    sizeBytes,
		},
	})

	rep.Status = "ready"
	rep.StorageKey = &storageKey
	rep.SHA256 = &shaDigest
	rep.SizeBytes = &sizeBytes

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"report": rep})
	return nil
}

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	scanID := chi.URLParam(r, "scanID")
	if scanID == "" {
		return httpx.ErrNotFound
	}

	reports, err := s.store.ListReports(r.Context(), orgID, scanID)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}
	if reports == nil {
		reports = []store.Report{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"reports": reports})
	return nil
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	reportID := chi.URLParam(r, "reportID")
	if reportID == "" {
		return httpx.ErrNotFound
	}

	rep, err := s.store.GetReport(r.Context(), orgID, reportID)
	if err != nil {
		if errors.Is(err, store.ErrReportNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"report": rep})
	return nil
}

func (s *Server) downloadReport(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	reportID := chi.URLParam(r, "reportID")
	if reportID == "" {
		return httpx.ErrNotFound
	}

	rep, err := s.store.GetReport(r.Context(), orgID, reportID)
	if err != nil {
		if errors.Is(err, store.ErrReportNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	if rep.Status != "ready" || rep.StorageKey == nil {
		return httpx.BadRequest("report is not ready for download")
	}

	rc, err := s.storage.Get(r.Context(), *rep.StorageKey)
	if err != nil {
		return httpx.ErrNotFound
	}
	defer rc.Close()

	filename := fmt.Sprintf("reversebug-report-%s.%s", rep.ScanID[:8], rep.Format)
	if rep.Format == "pdf" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		filename = fmt.Sprintf("reversebug-report-%s.html", rep.ScanID[:8])
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	if rep.SizeBytes != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", *rep.SizeBytes))
	}

	_, _ = io.Copy(w, rc)
	return nil
}
