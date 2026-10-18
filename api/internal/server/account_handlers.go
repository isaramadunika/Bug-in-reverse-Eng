package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/tetraneurons/reversebug/api/internal/auth"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	rbmail "github.com/tetraneurons/reversebug/api/internal/mail"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

const OnboardingSteps = 12

func (s *Server) me(w http.ResponseWriter, r *http.Request) error {
	v, err := s.view(r.Context(), userFrom(r.Context()))
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

type updateMeReq struct {
	DisplayName     *string `json:"display_name"`
	ThemePreference *string `json:"theme_preference"`
}

func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) error {
	var req updateMeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	fields := map[string]string{}
	if req.DisplayName != nil {
		n := strings.TrimSpace(*req.DisplayName)
		if l := len([]rune(n)); l < 1 || l > 120 {
			fields["display_name"] = "Name must be between 1 and 120 characters."
		}
		req.DisplayName = &n
	}
	if req.ThemePreference != nil {
		switch *req.ThemePreference {
		case "dark", "light", "system":
		default:
			fields["theme_preference"] = "Theme must be dark, light or system."
		}
	}
	if len(fields) > 0 {
		return httpx.Validation(fields)
	}
	u := userFrom(r.Context())
	if err := s.store.UpdateProfile(r.Context(), u.ID, req.DisplayName, req.ThemePreference); err != nil {
		return err
	}
	fresh, err := s.store.UserByID(r.Context(), u.ID)
	if err != nil {
		return err
	}
	v, err := s.view(r.Context(), fresh)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, v)
	return nil
}

type changePasswordReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) error {
	u, sess := userFrom(r.Context()), sessionFrom(r.Context())
	if err := s.rateLimit(r, "chpw:user:"+u.ID, 10, time.Hour); err != nil {
		return err
	}
	var req changePasswordReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if ok, _, err := auth.VerifyPassword(req.CurrentPassword, u.PasswordHash, s.argon); err != nil || !ok {
		s.auditReq(r, "account.password_change", "user", u.ID, "failure", nil)
		return httpx.Validation(map[string]string{"current_password": "Current password is incorrect."})
	}
	if err := auth.ValidatePasswordPolicy(req.NewPassword, u.Email); err != nil {
		return httpx.Validation(map[string]string{"new_password": err.Error()})
	}
	hash, err := auth.HashPassword(req.NewPassword, s.argon)
	if err != nil {
		return err
	}
	if err := s.store.UpdatePasswordHash(r.Context(), u.ID, hash); err != nil {
		return err
	}
	n, _ := s.store.RevokeUserSessions(r.Context(), u.ID, sess.ID)
	s.auditReq(r, "account.password_change", "user", u.ID, "success", map[string]any{"other_sessions_revoked": n})
	s.sendMail(r.Context(), rbmail.Message{To: u.Email, Subject: "Your ReverseBug password was changed",
		Text: "Your password was changed and your other sessions were signed out. If this was not you, reset your password immediately.\n"})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type onboardingReq struct {
	Step      int  `json:"step"`
	Completed bool `json:"completed"`
}

func (s *Server) updateOnboarding(w http.ResponseWriter, r *http.Request) error {
	var req onboardingReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Step < 0 || req.Step > OnboardingSteps {
		return httpx.Validation(map[string]string{"step": "Step is out of range."})
	}
	u := userFrom(r.Context())
	if err := s.store.SetOnboarding(r.Context(), u.ID, req.Step, req.Completed); err != nil {
		return err
	}
	if req.Completed {
		s.auditReq(r, "account.onboarding_completed", "user", u.ID, "success", map[string]any{"step": req.Step})
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) replayOnboarding(w http.ResponseWriter, r *http.Request) error {
	if err := s.store.ResetOnboarding(r.Context(), userFrom(r.Context()).ID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) error {
	list, err := s.store.ListSessions(r.Context(), userFrom(r.Context()).ID, sessionFrom(r.Context()).ID)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": list})
	return nil
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "sessionID")
	u := userFrom(r.Context())
	ok, err := s.store.RevokeSession(r.Context(), u.ID, id)
	if err != nil {
		// Malformed UUIDs surface as database errors; treat as not found.
		return httpx.ErrNotFound
	}
	if !ok {
		return httpx.ErrNotFound
	}
	s.auditReq(r, "account.session_revoked", "session", id, "success", nil)
	if id == sessionFrom(r.Context()).ID {
		s.clearSessionCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	n, err := s.store.RevokeUserSessions(r.Context(), u.ID, sessionFrom(r.Context()).ID)
	if err != nil {
		return err
	}
	s.auditReq(r, "account.sessions_revoked", "user", u.ID, "success", map[string]any{"count": n})
	httpx.WriteJSON(w, http.StatusOK, map[string]int64{"revoked": n})
	return nil
}

// ---- MFA enrollment ----

func (s *Server) mfaSetup(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	if u.MFAEnabledAt != nil {
		return httpx.NewError(http.StatusConflict, "mfa_already_enabled", "Multi-factor authentication is already enabled.")
	}
	secret, url, err := auth.NewTOTP(u.Email)
	if err != nil {
		return err
	}
	enc, err := s.sealer.Seal([]byte(secret), []byte(u.ID))
	if err != nil {
		return err
	}
	if err := s.store.SetPendingTOTP(r.Context(), u.ID, enc); err != nil {
		return err
	}
	// The secret is returned once so the user can enroll an authenticator app.
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": url})
	return nil
}

func (s *Server) mfaEnable(w http.ResponseWriter, r *http.Request) error {
	u, sess := userFrom(r.Context()), sessionFrom(r.Context())
	if err := s.rateLimit(r, "mfa:user:"+u.ID, 10, 15*time.Minute); err != nil {
		return err
	}
	var req codeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if u.MFAEnabledAt != nil {
		return httpx.NewError(http.StatusConflict, "mfa_already_enabled", "Multi-factor authentication is already enabled.")
	}
	ok, err := s.checkTOTP(r.Context(), u, req.Code)
	if err != nil || !ok {
		return httpx.Validation(map[string]string{"code": "The verification code is incorrect. Start setup again if needed."})
	}
	if err := s.store.EnableMFA(r.Context(), u.ID); err != nil {
		return err
	}
	_ = s.store.MarkSessionMFAVerified(r.Context(), sess.ID)
	n, _ := s.store.RevokeUserSessions(r.Context(), u.ID, sess.ID)
	s.auditReq(r, "account.mfa_enabled", "user", u.ID, "success", map[string]any{"other_sessions_revoked": n})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	if err := s.rateLimit(r, "mfa:user:"+u.ID, 10, 15*time.Minute); err != nil {
		return err
	}
	var req codeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if u.MFAEnabledAt == nil {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	if u.PlatformRole != "user" && s.cfg.AdminRequireMFA {
		return httpx.NewError(http.StatusForbidden, "mfa_required_for_role", "Administrators cannot disable multi-factor authentication.")
	}
	if ok, _, err := auth.VerifyPassword(req.Password, u.PasswordHash, s.argon); err != nil || !ok {
		return httpx.Validation(map[string]string{"password": "Password is incorrect."})
	}
	if ok, err := s.checkTOTP(r.Context(), u, req.Code); err != nil || !ok {
		return httpx.Validation(map[string]string{"code": "The verification code is incorrect."})
	}
	if err := s.store.DisableMFA(r.Context(), u.ID); err != nil {
		return err
	}
	s.auditReq(r, "account.mfa_disabled", "user", u.ID, "success", nil)
	s.sendMail(r.Context(), rbmail.Message{To: u.Email, Subject: "Multi-factor authentication disabled",
		Text: "Multi-factor authentication was disabled on your ReverseBug account. If this was not you, reset your password immediately.\n"})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- export and deletion ----

func (s *Server) exportAccount(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	if err := s.rateLimit(r, "export:user:"+u.ID, 5, time.Hour); err != nil {
		return err
	}
	ms, err := s.store.Memberships(r.Context(), u.ID)
	if err != nil {
		return err
	}
	sessions, err := s.store.ListSessions(r.Context(), u.ID, "")
	if err != nil {
		return err
	}
	s.auditReq(r, "account.export", "user", u.ID, "success", nil)
	w.Header().Set("Content-Disposition", `attachment; filename="reversebug-account-export.json"`)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"format_version": 1, "exported_at": s.now().UTC(), "user": u, "memberships": ms, "active_sessions": sessions,
	})
	return nil
}

func (s *Server) requestDeletion(w http.ResponseWriter, r *http.Request) error {
	u := userFrom(r.Context())
	var req codeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if ok, _, err := auth.VerifyPassword(req.Password, u.PasswordHash, s.argon); err != nil || !ok {
		return httpx.Validation(map[string]string{"password": "Password is incorrect."})
	}
	if u.MFAEnabledAt != nil {
		if ok, err := s.checkTOTP(r.Context(), u, req.Code); err != nil || !ok {
			return httpx.Validation(map[string]string{"code": "The verification code is incorrect."})
		}
	}
	if err := s.store.RequestDeletion(r.Context(), u.ID); err != nil {
		return err
	}
	_, _ = s.store.RevokeUserSessions(r.Context(), u.ID, "")
	s.auditReq(r, "account.deletion_requested", "user", u.ID, "success", nil)
	s.sendMail(r.Context(), rbmail.Message{To: u.Email, Subject: "ReverseBug account deletion requested",
		Text: "Your account is scheduled for deletion and has been signed out. Contact support within 14 days to cancel.\n"})
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusAccepted)
	return nil
}

// ---- dashboard, public, admin ----

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) error {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 365 {
			return httpx.Validation(map[string]string{"days": "days must be between 1 and 365."})
		}
		days = n
	}
	var project *string
	if v := r.URL.Query().Get("project_id"); v != "" {
		if !isUUID(v) {
			return httpx.Validation(map[string]string{"project_id": "Invalid project id."})
		}
		project = &v
	}
	d, err := s.store.Dashboard(r.Context(), userFrom(r.Context()).ID, days, project)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, d)
	return nil
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}

func (s *Server) publicPlans(w http.ResponseWriter, r *http.Request) error {
	plans, err := s.store.PublicPlans(r.Context())
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": plans,
		"note": "Launch prices are proposals and are configurable by administrators."})
	return nil
}

func (s *Server) adminVerifyAudit(w http.ResponseWriter, r *http.Request) error {
	broken, checked, err := s.audit.Verify(r.Context())
	if err != nil {
		return err
	}
	s.auditReq(r, "admin.audit_verify", "audit_events", "", "success", map[string]any{"checked": checked, "broken_id": broken})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"checked": checked, "intact": broken == 0, "first_broken_id": broken})
	return nil
}

var _ = errors.New
var _ = store.ErrNotFound
