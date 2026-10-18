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

func (s *Server) resolveOrgID(r *http.Request, u *store.User) (string, error) {
	if explicit := r.Header.Get("X-Organization-ID"); explicit != "" {
		return explicit, nil
	}
	if k := apiKeyFrom(r.Context()); k != nil && k.OrganizationID != "" {
		return k.OrganizationID, nil
	}
	orgID, err := s.store.UserPersonalOrgID(r.Context(), u.ID)
	if err != nil {
		return "", err
	}
	return orgID, nil
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	projects, err := s.store.ListProjects(r.Context(), orgID)
	if err != nil {
		return err
	}
	if projects == nil {
		projects = []store.ProjectSummary{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"projects": projects})
	return nil
}

type createProjectReq struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	PackageName      *string  `json:"package_name"`
	ApplicationOwner string   `json:"application_owner"`
	Environment      string   `json:"environment"`
	Tags             []string `json:"tags"`
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	var req createProjectReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) < 1 || len(req.Name) > 120 {
		return httpx.BadRequest("Project name must be between 1 and 120 characters")
	}

	proj, err := s.store.CreateProject(r.Context(), orgID, u.ID, &store.CreateProjectInput{
		Name:             req.Name,
		Description:      strings.TrimSpace(req.Description),
		PackageName:      req.PackageName,
		ApplicationOwner: strings.TrimSpace(req.ApplicationOwner),
		Environment:      req.Environment,
		Tags:             req.Tags,
	})
	if err != nil {
		return err
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "project.created",
		TargetType:  "project",
		TargetID:    proj.ID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata:    map[string]any{"name": proj.Name, "package_name": proj.PackageName},
	})

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"project": proj})
	return nil
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	proj, err := s.store.GetProject(r.Context(), orgID, projectID)
	if errors.Is(err, store.ErrProjectNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"project": proj})
	return nil
}

type updateProjectReq struct {
	Name             *string   `json:"name"`
	Description      *string   `json:"description"`
	PackageName      *string   `json:"package_name"`
	ApplicationOwner *string   `json:"application_owner"`
	Environment      *string   `json:"environment"`
	Tags             *[]string `json:"tags"`
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	var req updateProjectReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}

	proj, err := s.store.UpdateProject(r.Context(), orgID, projectID, &store.UpdateProjectInput{
		Name:             req.Name,
		Description:      req.Description,
		PackageName:      req.PackageName,
		ApplicationOwner: req.ApplicationOwner,
		Environment:      req.Environment,
		Tags:             req.Tags,
	})
	if errors.Is(err, store.ErrProjectNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "project.updated",
		TargetType:  "project",
		TargetID:    proj.ID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
		Metadata:    map[string]any{"name": proj.Name},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"project": proj})
	return nil
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	err = s.store.DeleteProject(r.Context(), orgID, projectID)
	if errors.Is(err, store.ErrProjectNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "project.deleted",
		TargetType:  "project",
		TargetID:    projectID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          s.ip(r),
		UserAgent:   r.UserAgent(),
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}

type createAuthReq struct {
	Basis                   string  `json:"basis"`
	ScopeDescription        string  `json:"scope_description"`
	AllowsDynamicValidation bool    `json:"allows_dynamic_validation"`
	ReferenceURL            *string `json:"reference_url"`
}

func (s *Server) createAuthorization(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	var req createAuthReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}

	validBases := map[string]bool{
		"owner":              true,
		"employer":           true,
		"client_contract":    true,
		"bug_bounty_program": true,
		"research_license":   true,
	}
	if !validBases[req.Basis] {
		return httpx.BadRequest("Invalid authorization basis; must be one of: owner, employer, client_contract, bug_bounty_program, research_license")
	}

	desc := strings.TrimSpace(req.ScopeDescription)
	if len(desc) < 10 || len(desc) > 4000 {
		return httpx.BadRequest("Scope description must be between 10 and 4000 characters")
	}

	clientIP := s.ip(r)
	rec, err := s.store.CreateAuthorizationRecord(r.Context(), orgID, projectID, u.ID, &store.CreateAuthRecordInput{
		Basis:                   req.Basis,
		ScopeDescription:        desc,
		AllowsDynamicValidation: req.AllowsDynamicValidation,
		ReferenceURL:            req.ReferenceURL,
	}, clientIP)
	if errors.Is(err, store.ErrProjectNotFound) {
		return httpx.ErrNotFound
	}
	if err != nil {
		return err
	}

	s.auditWrite(r.Context(), audit.Event{
		ActorType:   "user",
		ActorUserID: &u.ID,
		Action:      "authorization_record.created",
		TargetType:  "authorization_record",
		TargetID:    rec.ID,
		OrgID:       &orgID,
		Outcome:     "success",
		IP:          clientIP,
		UserAgent:   r.UserAgent(),
		Metadata:    map[string]any{"basis": rec.Basis, "project_id": projectID},
	})

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"authorization": rec})
	return nil
}

func (s *Server) listAuthorizations(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}
	projectID := chi.URLParam(r, "projectID")

	records, err := s.store.ListAuthorizationRecords(r.Context(), orgID, projectID)
	if err != nil {
		return err
	}
	if records == nil {
		records = []store.AuthorizationRecord{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"authorizations": records})
	return nil
}
