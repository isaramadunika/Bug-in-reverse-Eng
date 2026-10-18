package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/tetraneurons/reversebug/api/internal/httpx"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

// ---------------------------------------------------------------------------
// API Key Management Handlers
// ---------------------------------------------------------------------------

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	keys, err := s.store.ListAPIKeys(r.Context(), orgID)
	if err != nil {
		return err
	}
	if keys == nil {
		keys = []store.APIKey{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": keys})
	return nil
}

type createAPIKeyReq struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays *int     `json:"expires_in_days"`
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	if err := s.rateLimit(r, "apikey:create:"+u.ID, 20, time.Hour); err != nil {
		return err
	}

	var req createAPIKeyReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}

	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) < 1 || len(req.Name) > 80 {
		return httpx.Validation(map[string]string{"name": "API key name must be between 1 and 80 characters."})
	}

	var expiresAt *time.Time
	if req.ExpiresInDays != nil {
		if *req.ExpiresInDays < 1 || *req.ExpiresInDays > 365 {
			return httpx.Validation(map[string]string{"expires_in_days": "Expiration must be between 1 and 365 days."})
		}
		t := s.now().UTC().AddDate(0, 0, *req.ExpiresInDays)
		expiresAt = &t
	}

	rawToken, key, err := s.store.CreateAPIKey(r.Context(), orgID, u.ID, req.Name, req.Scopes, expiresAt, s.cfg.APIKeyPepper)
	if err != nil {
		return httpx.NewError(http.StatusBadRequest, "api_key_create_failed", err.Error())
	}

	s.auditReq(r, "api_key.create", "api_key", key.ID, "success", map[string]any{
		"name":   key.Name,
		"scopes": key.Scopes,
	})

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"api_key": key,
		"token":   rawToken,
		"warning": "This token is only shown once. Save it in a secure location.",
	})
	return nil
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	keyID := chi.URLParam(r, "keyID")
	if !isUUID(keyID) {
		return httpx.Validation(map[string]string{"keyID": "Invalid API key ID format."})
	}

	err = s.store.RevokeAPIKey(r.Context(), orgID, keyID, u.ID)
	if err != nil {
		if errors.Is(err, store.ErrAPIKeyNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	s.auditReq(r, "api_key.revoke", "api_key", keyID, "success", nil)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------------------
// Billing & Subscriptions Handlers
// ---------------------------------------------------------------------------

func (s *Server) getSubscription(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	sub, err := s.store.GetSubscription(r.Context(), orgID)
	if err != nil {
		return err
	}

	httpx.WriteJSON(w, http.StatusOK, sub)
	return nil
}

type upgradeSubscriptionReq struct {
	PlanID string `json:"plan_id"`
}

func (s *Server) upgradeSubscription(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	if err := s.rateLimit(r, "billing:upgrade:"+u.ID, 10, time.Hour); err != nil {
		return err
	}

	var req upgradeSubscriptionReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}

	req.PlanID = strings.TrimSpace(req.PlanID)
	if req.PlanID == "" {
		return httpx.Validation(map[string]string{"plan_id": "Plan ID is required."})
	}

	sub, err := s.store.UpgradeSubscription(r.Context(), orgID, req.PlanID)
	if err != nil {
		if errors.Is(err, store.ErrPlanNotFound) {
			return httpx.NewError(http.StatusBadRequest, "invalid_plan", "The selected subscription plan does not exist.")
		}
		return err
	}

	s.auditReq(r, "billing.upgrade", "subscription", sub.ID, "success", map[string]any{
		"plan_id": req.PlanID,
	})

	httpx.WriteJSON(w, http.StatusOK, sub)
	return nil
}

func (s *Server) cancelSubscription(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	orgID, err := s.resolveOrgID(r, u)
	if err != nil {
		return err
	}

	err = s.store.CancelSubscription(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, store.ErrSubscriptionNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}

	s.auditReq(r, "billing.cancel", "subscription", orgID, "success", nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "cancellation_scheduled"})
	return nil
}

// ---------------------------------------------------------------------------
// Administrator Console Handlers
// ---------------------------------------------------------------------------

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	limit := 25
	offset := 0
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	if o := q.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	filter := store.AdminUserFilter{
		Search:       strings.TrimSpace(q.Get("search")),
		Status:       strings.TrimSpace(q.Get("status")),
		PlatformRole: strings.TrimSpace(q.Get("platform_role")),
		Limit:        limit,
		Offset:       offset,
	}

	users, total, err := s.store.ListAdminUsers(r.Context(), filter)
	if err != nil {
		return err
	}
	if users == nil {
		users = []store.AdminUserSummary{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
	return nil
}

type adminUpdateUserReq struct {
	Status        string `json:"status"` // 'active', 'suspended', 'locked'
	LockedMinutes *int   `json:"locked_minutes,omitempty"`
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request) error {
	targetUserID := chi.URLParam(r, "userID")
	if !isUUID(targetUserID) {
		return httpx.Validation(map[string]string{"userID": "Invalid user ID format."})
	}

	var req adminUpdateUserReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}

	req.Status = strings.TrimSpace(req.Status)
	if req.Status != "active" && req.Status != "suspended" && req.Status != "locked" {
		return httpx.Validation(map[string]string{"status": "Status must be 'active', 'suspended', or 'locked'."})
	}

	var lockedUntil *time.Time
	if req.LockedMinutes != nil && *req.LockedMinutes > 0 {
		t := s.now().UTC().Add(time.Duration(*req.LockedMinutes) * time.Minute)
		lockedUntil = &t
	}

	err := s.store.UpdateUserStatusByAdmin(r.Context(), targetUserID, req.Status, lockedUntil)
	if err != nil {
		return err
	}

	s.auditReq(r, "admin.user_update", "user", targetUserID, "success", map[string]any{
		"status":       req.Status,
		"locked_until": lockedUntil,
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	return nil
}

func (s *Server) adminStats(w http.ResponseWriter, r *http.Request) error {
	st, err := s.store.GetPlatformStats(r.Context())
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, st)
	return nil
}

func (s *Server) adminListAuditEvents(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	limit := 50
	offset := 0
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if o := q.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	var actionFilter *string
	if a := strings.TrimSpace(q.Get("action")); a != "" {
		actionFilter = &a
	}

	events, err := s.store.ListAuditEvents(r.Context(), limit, offset, actionFilter)
	if err != nil {
		return err
	}
	if events == nil {
		events = []store.AuditEventRow{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": events})
	return nil
}
