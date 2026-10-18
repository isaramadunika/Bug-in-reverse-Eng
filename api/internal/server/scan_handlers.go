package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

type createScanReq struct {
	ArtifactVersionID     string  `json:"artifact_version_id"`
	ProfileID             string  `json:"profile_id"`
	AuthorizationRecordID *string `json:"authorization_record_id"`
	IdempotencyKey        string  `json:"idempotency_key"`
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	var req createScanReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}

	req.ArtifactVersionID = strings.TrimSpace(req.ArtifactVersionID)
	if req.ArtifactVersionID == "" {
		return httpx.BadRequest("artifact_version_id is required")
	}

	req.ProfileID = strings.TrimSpace(req.ProfileID)
	if req.ProfileID == "" {
		req.ProfileID = "standard"
	}
	if req.ProfileID != "quick" && req.ProfileID != "standard" && req.ProfileID != "deep" {
		return httpx.BadRequest("profile_id must be quick, standard, or deep")
	}

	// Determine active authorization record
	var authRecordID string
	if req.AuthorizationRecordID != nil && *req.AuthorizationRecordID != "" {
		authRecordID = *req.AuthorizationRecordID
	} else {
		hasActive, activeID, err := s.store.HasActiveAuthorization(r.Context(), projectID)
		if err != nil {
			return err
		}
		if !hasActive {
			return httpx.BadRequest("Project has no active Attestation of Authorization. An authorization record must be recorded prior to initiating scans.")
		}
		authRecordID = activeID
	}

	scan, err := s.store.CreateScan(r.Context(), orgID, projectID, req.ArtifactVersionID, req.ProfileID, authRecordID, u.ID, req.IdempotencyKey)
	if errors.Is(err, store.ErrProjectNotFound) {
		return httpx.ErrNotFound
	}
	if errors.Is(err, store.ErrUnauthorizedScan) {
		return httpx.BadRequest("Specified authorization record is invalid or expired")
	}
	if errors.Is(err, store.ErrInvalidProfile) {
		return httpx.BadRequest("Invalid scan profile specified")
	}
	if err != nil {
		return err
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "scan.enqueued",
		TargetType:  "scan",
		TargetID:    scan.ID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata: map[string]any{
			"project_id":          projectID,
			"profile_id":          req.ProfileID,
			"artifact_version_id": req.ArtifactVersionID,
			"auth_record_id":      authRecordID,
		},
	})

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"scan": scan})
	return nil
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	scans, err := s.store.ListScans(r.Context(), orgID, projectID)
	if err != nil {
		return err
	}
	if scans == nil {
		scans = []store.ScanSummary{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scans": scans})
	return nil
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	scanID := chi.URLParam(r, "scanID")

	scan, err := s.store.GetScan(r.Context(), orgID, scanID)
	if errors.Is(err, store.ErrScanNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scan": scan})
	return nil
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	scanID := chi.URLParam(r, "scanID")

	err = s.store.CancelScan(r.Context(), orgID, scanID)
	if err != nil {
		return httpx.BadRequest(err.Error())
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "scan.cancelled",
		TargetType:  "scan",
		TargetID:    scanID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "cancelling"})
	return nil
}
