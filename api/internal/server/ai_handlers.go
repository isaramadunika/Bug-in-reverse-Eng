package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/tetraneurons/reversebug/api/internal/ai"
	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

type investigateReq struct {
	Agent string `json:"agent"` // "validation_analyst" | "re_analyst" | "remediation_advisor"
}

func (s *Server) investigateFinding(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	scanID := chi.URLParam(r, "scanID")
	findingID := chi.URLParam(r, "findingID")
	if scanID == "" || findingID == "" {
		return httpx.ErrNotFound
	}

	var req investigateReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		req.Agent = "validation_analyst"
	}
	if req.Agent == "" {
		req.Agent = "validation_analyst"
	}

	role := ai.AgentRole(req.Agent)
	switch role {
	case ai.RoleValidationAnalyst, ai.RoleReAnalyst, ai.RoleSecretAuditor, ai.RoleRiskAssessor, ai.RoleRemediationAdvisor, ai.RoleReportAnalyst:
	default:
		role = ai.RoleValidationAnalyst
	}

	res, err := s.ai.InvestigateFinding(r.Context(), orgID, scanID, findingID, role)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) || errors.Is(err, store.ErrFindingNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "ai.investigation_executed",
		TargetType:  "finding",
		TargetID:    findingID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata: map[string]any{
			"agent":        string(role),
			"run_id":       res.RunID,
			"verdict":      res.Analysis.Verdict,
			"tokens_total": res.InputTokens + res.OutputTokens,
		},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"investigation": res})
	return nil
}

func (s *Server) listFindingAnalyses(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	scanID := chi.URLParam(r, "scanID")
	findingID := chi.URLParam(r, "findingID")
	if scanID == "" || findingID == "" {
		return httpx.ErrNotFound
	}

	analyses, err := s.store.ListAIAnalyses(r.Context(), orgID, scanID, &findingID)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}
	if analyses == nil {
		analyses = []store.AIAnalysis{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"analyses": analyses,
		"count":    len(analyses),
	})
	return nil
}

func (s *Server) getAnalysis(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	analysisID := chi.URLParam(r, "analysisID")
	if analysisID == "" {
		return httpx.ErrNotFound
	}

	analysis, err := s.store.GetAIAnalysis(r.Context(), orgID, analysisID)
	if err != nil {
		if errors.Is(err, store.ErrAIAnalysisNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"analysis": analysis})
	return nil
}

func (s *Server) askCopilot(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	scanID := chi.URLParam(r, "scanID")
	if scanID == "" {
		return httpx.ErrNotFound
	}

	var req ai.CopilotQuestionRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	req.Question = strings.TrimSpace(req.Question)
	if len(req.Question) < 3 {
		return httpx.BadRequest("Question must be at least 3 characters long")
	}

	ans, err := s.ai.AskCopilot(r.Context(), orgID, scanID, req.Question)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "ai.copilot_asked",
		TargetType:  "scan",
		TargetID:    scanID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata: map[string]any{
			"question_length": len(req.Question),
			"cited_findings":  len(ans.CitedFindingIDs),
		},
	})

	httpx.WriteJSON(w, http.StatusOK, ans)
	return nil
}
