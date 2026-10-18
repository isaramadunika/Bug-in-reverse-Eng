package server

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	scanID := chi.URLParam(r, "scanID")
	if scanID == "" {
		return httpx.ErrNotFound
	}

	filter := store.FindingFilter{}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		filter.Severity = &sev
	}
	if rev := r.URL.Query().Get("review_status"); rev != "" {
		filter.ReviewStatus = &rev
	}
	if cat := r.URL.Query().Get("category"); cat != "" {
		filter.Category = &cat
	}
	if reach := r.URL.Query().Get("reachability"); reach != "" {
		filter.Reachability = &reach
	}
	if q := r.URL.Query().Get("search"); q != "" {
		filter.Search = &q
	}

	findings, err := s.store.ListFindings(r.Context(), orgID, scanID, filter)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}
	if findings == nil {
		findings = []store.Finding{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"findings": findings,
		"count":    len(findings),
	})
	return nil
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		return httpx.ErrNotFound
	}

	finding, err := s.store.GetFinding(r.Context(), orgID, findingID)
	if err != nil {
		if errors.Is(err, store.ErrFindingNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"finding": finding})
	return nil
}

func (s *Server) updateFinding(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		return httpx.ErrNotFound
	}

	var in store.UpdateFindingReviewInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return err
	}

	updated, err := s.store.UpdateFindingReview(r.Context(), orgID, findingID, in)
	if err != nil {
		if errors.Is(err, store.ErrFindingNotFound) {
			return httpx.ErrNotFound
		}
		return httpx.BadRequest(err.Error())
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "finding.triage_updated",
		TargetType:  "finding",
		TargetID:    findingID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata: map[string]any{
			"review_status": in.ReviewStatus,
		},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"finding": updated})
	return nil
}

func (s *Server) getEvidenceGraph(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	scanID := chi.URLParam(r, "scanID")
	if scanID == "" {
		return httpx.ErrNotFound
	}

	graph, err := s.store.GetEvidenceGraph(r.Context(), orgID, scanID)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	httpx.WriteJSON(w, http.StatusOK, graph)
	return nil
}

type SourceFileResp struct {
	Path         string   `json:"path"`
	Content      string   `json:"content"`
	SizeBytes    int64    `json:"size_bytes"`
	IsTruncated  bool     `json:"is_truncated"`
	Language     string   `json:"language"`
	ArchiveFiles []string `json:"archive_files,omitempty"`
}

func (s *Server) getSourceFile(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	scanID := chi.URLParam(r, "scanID")
	if scanID == "" {
		return httpx.ErrNotFound
	}

	storageKey, _, _, err := s.store.GetScanArtifactStorageKey(r.Context(), orgID, scanID)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	localPath, err := s.storage.LocalPath(storageKey)
	if err != nil {
		return httpx.ErrNotFound
	}

	zr, err := zip.OpenReader(localPath)
	if err != nil {
		return httpx.BadRequest("failed to open artifact archive")
	}
	defer zr.Close()

	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		requestedPath = "AndroidManifest.xml"
	}
	cleanReq := path.Clean(strings.TrimPrefix(requestedPath, "/"))
	if strings.Contains(cleanReq, "..") {
		return httpx.BadRequest("invalid file path")
	}

	var archiveFileList []string
	var targetFile *zip.File

	for _, f := range zr.File {
		archiveFileList = append(archiveFileList, f.Name)
		if f.Name == cleanReq || strings.TrimPrefix(f.Name, "/") == cleanReq {
			targetFile = f
		}
	}

	if len(archiveFileList) > 200 {
		archiveFileList = archiveFileList[:200]
	}

	if targetFile == nil {
		httpx.WriteJSON(w, http.StatusOK, SourceFileResp{
			Path:         cleanReq,
			Content:      "",
			SizeBytes:    0,
			IsTruncated:  false,
			Language:     detectLanguage(cleanReq),
			ArchiveFiles: archiveFileList,
		})
		return nil
	}

	rc, err := targetFile.Open()
	if err != nil {
		return httpx.BadRequest("failed to read archive entry")
	}
	defer rc.Close()

	const maxRead = 2 * 1024 * 1024
	lr := io.LimitReader(rc, maxRead+1)
	rawBytes, err := io.ReadAll(lr)
	if err != nil {
		return httpx.BadRequest("failed to read file content")
	}

	isTruncated := false
	if len(rawBytes) > maxRead {
		isTruncated = true
		rawBytes = rawBytes[:maxRead]
	}

	var contentStr string
	if utf8.Valid(rawBytes) {
		contentStr = string(rawBytes)
	} else {
		contentStr = extractPrintableOrSummary(rawBytes)
	}

	httpx.WriteJSON(w, http.StatusOK, SourceFileResp{
		Path:         targetFile.Name,
		Content:      contentStr,
		SizeBytes:    int64(targetFile.UncompressedSize64),
		IsTruncated:  isTruncated,
		Language:     detectLanguage(targetFile.Name),
		ArchiveFiles: archiveFileList,
	})
	return nil
}

func detectLanguage(filePath string) string {
	lower := strings.ToLower(filePath)
	switch {
	case strings.HasSuffix(lower, ".xml"):
		return "xml"
	case strings.HasSuffix(lower, ".json"):
		return "json"
	case strings.HasSuffix(lower, ".java"):
		return "java"
	case strings.HasSuffix(lower, ".kt"):
		return "kotlin"
	case strings.HasSuffix(lower, ".smali"):
		return "smali"
	case strings.HasSuffix(lower, ".properties") || strings.HasSuffix(lower, ".prop"):
		return "properties"
	case strings.HasSuffix(lower, ".js"):
		return "javascript"
	default:
		return "plaintext"
	}
}

func extractPrintableOrSummary(b []byte) string {
	var buf bytes.Buffer
	buf.WriteString("// Binary format preview - Printable tokens extracted from archive entry:\n\n")
	var current []rune
	for _, r := range string(b) {
		if (r >= 32 && r <= 126) || r == '\n' || r == '\t' {
			current = append(current, r)
		} else {
			if len(current) >= 4 {
				buf.WriteString(string(current))
				buf.WriteString("\n")
			}
			current = nil
		}
	}
	if len(current) >= 4 {
		buf.WriteString(string(current))
	}
	if buf.Len() < 50 {
		return fmt.Sprintf("// Binary content (%d bytes) is not plain text.", len(b))
	}
	return buf.String()
}
