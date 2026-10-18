package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/auth"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	rbmail "github.com/tetraneurons/reversebug/api/internal/mail"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

const (
	verifyTokenTTL   = 24 * time.Hour
	resetTokenTTL    = 30 * time.Minute
	lockoutThreshold = 10
	lockoutDuration  = 15 * time.Minute
)

func (s *Server) ip(r *http.Request) string { return httpx.ClientIP(r, s.cfg.TrustProxyHeader) }

func (s *Server) auditReq(r *http.Request, action, ttype, tid, outcome string, md map[string]any) {
	e := audit.Event{Action: action, TargetType: ttype, TargetID: tid, Outcome: outcome,
		IP: s.ip(r), UserAgent: r.UserAgent(), Metadata: md, ActorType: "anonymous"}
	if u := userFrom(r.Context()); u != nil {
		e.ActorType, e.ActorUserID = "user", &u.ID
	}
	s.auditWrite(r.Context(), e)
}

func (s *Server) auditWrite(ctx context.Context, e audit.Event) {
	if err := s.audit.Record(ctx, e); err != nil {
		slog.ErrorContext(ctx, "audit write failed", "err", err, "action", e.Action)
	}
}

func normalizeEmail(raw string) (string, bool) {
	e := strings.TrimSpace(raw)
	if len(e) > 254 {
		return "", false
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e || !strings.Contains(e[strings.LastIndex(e, "@"):], ".") {
		return "", false
	}
	return strings.ToLower(e), true
}

type userView struct {
	*store.User
	EmailVerified bool               `json:"email_verified"`
	MFAEnabled    bool               `json:"mfa_enabled"`
	ShowOnboarding bool              `json:"show_onboarding"`
	Memberships   []store.Membership `json:"memberships"`
}

func (s *Server) view(ctx context.Context, u *store.User) (*userView, error) {
	ms, err := s.store.Memberships(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return &userView{User: u, EmailVerified: u.EmailVerifiedAt != nil, MFAEnabled: u.MFAEnabledAt != nil,
		ShowOnboarding: u.OnboardingCompletedAt == nil, Memberships: ms}, nil
}

// ---------------------------------------------------------------------------

type registerReq struct {
	Email          string `json:"email"`
	DisplayName    string `json:"display_name"`
	Password       string `json:"password"`
	AcceptTerms    bool   `json:"accept_terms"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) error {
	if err := s.rateLimit(r, "register:ip:"+s.ip(r), 10, time.Hour); err != nil {
		return err
	}
	var req registerReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	fields := map[string]string{}
	email, ok := normalizeEmail(req.Email)
	if !ok {
		fields["email"] = "Enter a valid email address."
	}
	name := strings.TrimSpace(req.DisplayName)
	if n := len([]rune(name)); n < 1 || n > 120 {
		fields["display_name"] = "Name must be between 1 and 120 characters."
	}
	if err := auth.ValidatePasswordPolicy(req.Password, email); err != nil {
		fields["password"] = err.Error()
	}
	if !req.AcceptTerms {
		fields["accept_terms"] = "You must accept the Terms of Service and Acceptable Use Policy."
	}
	if len(fields) > 0 {
		return httpx.Validation(fields)
	}

	hash, err := auth.HashPassword(req.Password, s.argon)
	if err != nil {
		return err
	}
	u, orgID, err := s.store.CreateUser(r.Context(), email, name, hash)
	if errors.Is(err, store.ErrEmailTaken) {
		// Do not reveal account existence: same response, notify the owner instead.
		s.sendMail(r.Context(), rbmail.Message{To: email, Subject: "ReverseBug registration attempt",
			Text: "Someone tried to create a ReverseBug account with this email address.\n\n" +
				"If this was you, sign in or reset your password at " + s.cfg.PublicBaseURL + "/forgot-password\n" +
				"If not, you can ignore this message."})
		s.auditReq(r, "auth.register", "user", "", "failure", map[string]any{"reason": "email_taken"})
		httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "verification_sent"})
		return nil
	}
	if err != nil {
		return err
	}
	s.auditWrite(r.Context(), audit.Event{ActorType: "user", ActorUserID: &u.ID, OrgID: &orgID,
		Action: "auth.register", TargetType: "user", TargetID: u.ID, Outcome: "success", IP: s.ip(r), UserAgent: r.UserAgent()})
	if err := s.issueVerification(r.Context(), u); err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "verification_sent"})
	return nil
}

func (s *Server) issueVerification(ctx context.Context, u *store.User) error {
	tok, err := auth.NewToken(32)
	if err != nil {
		return err
	}
	if err := s.store.CreateUserToken(ctx, u.ID, "email_verify", auth.HashToken(tok), verifyTokenTTL); err != nil {
		return err
	}
	s.sendMail(ctx, rbmail.Message{To: u.Email, Subject: "Verify your ReverseBug email address",
		Text: fmt.Sprintf("Hi %s,\n\nConfirm your email address to activate ReverseBug:\n\n%s/verify-email?token=%s\n\n"+
			"This link expires in 24 hours. If you did not create an account, ignore this message.\n",
			u.DisplayName, s.cfg.PublicBaseURL, tok)})
	return nil
}

type tokenReq struct {
	Token string `json:"token"`
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) error {
	if err := s.rateLimit(r, "verify:ip:"+s.ip(r), 30, time.Hour); err != nil {
		return err
	}
	var req tokenReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Token == "" || len(req.Token) > 128 {
		return httpx.NewError(http.StatusBadRequest, "invalid_token", "This verification link is invalid or has expired.")
	}
	uid, err := s.store.ConsumeUserToken(r.Context(), "email_verify", auth.HashToken(req.Token))
	if errors.Is(err, store.ErrNotFound) {
		return httpx.NewError(http.StatusBadRequest, "invalid_token", "This verification link is invalid or has expired.")
	}
	if err != nil {
		return err
	}
	if err := s.store.MarkEmailVerified(r.Context(), uid); err != nil {
		return err
	}
	s.auditWrite(r.Context(), audit.Event{ActorType: "user", ActorUserID: &uid, Action: "auth.email_verified",
		TargetType: "user", TargetID: uid, Outcome: "success", IP: s.ip(r), UserAgent: r.UserAgent()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "verified"})
	return nil
}

type emailReq struct {
	Email string `json:"email"`
}

func (s *Server) resendVerification(w http.ResponseWriter, r *http.Request) error {
	if err := s.rateLimit(r, "resend:ip:"+s.ip(r), 5, time.Hour); err != nil {
		return err
	}
	var u *store.User
	if cur := userFrom(r.Context()); cur != nil {
		u = cur
		// Session requests carry no body; tolerate an empty one.
	} else {
		var req emailReq
		if err := httpx.DecodeJSON(r, &req); err != nil {
			return err
		}
		if email, ok := normalizeEmail(req.Email); ok {
			u, _ = s.store.UserByEmail(r.Context(), email)
		}
	}
	if u != nil && u.EmailVerifiedAt == nil && u.Status == "active" {
		if err := s.rateLimit(r, "resend:user:"+u.ID, 3, time.Hour); err != nil {
			return err
		}
		if err := s.issueVerification(r.Context(), u); err != nil {
			return err
		}
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "verification_sent"})
	return nil
}

// ---------------------------------------------------------------------------

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type sessionResp struct {
	Authenticated bool      `json:"authenticated"`
	MFARequired   bool      `json:"mfa_required"`
	CSRFToken     string    `json:"csrf_token,omitempty"`
	User          *userView `json:"user,omitempty"`
}

var errBadCredentials = httpx.NewError(http.StatusUnauthorized, "invalid_credentials", "Email or password is incorrect.")

func (s *Server) login(w http.ResponseWriter, r *http.Request) error {
	ip := s.ip(r)
	if err := s.rateLimit(r, "login:ip:"+ip, 30, 15*time.Minute); err != nil {
		s.auditReq(r, "auth.login", "", "", "denied", map[string]any{"reason": "ip_rate_limited"})
		return err
	}
	var req loginReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	email, ok := normalizeEmail(req.Email)
	if !ok || len(req.Password) == 0 || len(req.Password) > auth.MaxPasswordLen {
		auth.EqualizeTiming(req.Password)
		return errBadCredentials
	}
	if err := s.rateLimit(r, "login:email:"+email, 10, 15*time.Minute); err != nil {
		s.auditReq(r, "auth.login", "", "", "denied", map[string]any{"reason": "account_rate_limited"})
		return err
	}

	u, err := s.store.UserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		auth.EqualizeTiming(req.Password)
		s.auditReq(r, "auth.login", "", "", "failure", map[string]any{"reason": "unknown_account"})
		return errBadCredentials
	}
	if err != nil {
		return err
	}
	fail := func(reason string) error {
		s.auditWrite(r.Context(), audit.Event{ActorType: "user", ActorUserID: &u.ID, Action: "auth.login",
			TargetType: "user", TargetID: u.ID, Outcome: "failure", IP: ip, UserAgent: r.UserAgent(),
			Metadata: map[string]any{"reason": reason}})
		return errBadCredentials
	}
	if u.LockedUntil != nil && u.LockedUntil.After(s.now()) {
		auth.EqualizeTiming(req.Password)
		_ = fail("locked")
		return httpx.NewError(http.StatusTooManyRequests, "account_locked",
			"Too many failed attempts. Try again later or reset your password.")
	}
	ok, rehash, err := auth.VerifyPassword(req.Password, u.PasswordHash, s.argon)
	if err != nil || !ok {
		if _, lerr := s.store.RecordLoginFailure(r.Context(), u.ID, lockoutThreshold, lockoutDuration); lerr != nil {
			slog.Error("record login failure", "err", lerr)
		}
		return fail("bad_password")
	}
	if u.Status != "active" {
		return fail("status_" + u.Status)
	}
	if rehash {
		if h, err := auth.HashPassword(req.Password, s.argon); err == nil {
			_ = s.store.UpdatePasswordHash(r.Context(), u.ID, h)
		}
	}
	if err := s.store.RecordLoginSuccess(r.Context(), u.ID); err != nil {
		return err
	}
	_ = s.limiter.Reset(r.Context(), "login:email:"+email)

	resp, err := s.startSession(w, r, u, u.MFAEnabledAt == nil)
	if err != nil {
		return err
	}
	s.auditWrite(r.Context(), audit.Event{ActorType: "user", ActorUserID: &u.ID, Action: "auth.login",
		TargetType: "user", TargetID: u.ID, Outcome: "success", IP: ip, UserAgent: r.UserAgent(),
		Metadata: map[string]any{"mfa_pending": resp.MFARequired}})
	httpx.WriteJSON(w, http.StatusOK, resp)
	return nil
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *store.User, mfaVerified bool) (*sessionResp, error) {
	tok, err := auth.NewToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := auth.NewToken(24)
	if err != nil {
		return nil, err
	}
	sess, err := s.store.CreateSession(r.Context(), u.ID, auth.HashToken(tok), csrf, mfaVerified,
		s.ip(r), r.UserAgent(), s.cfg.SessionIdleTimeout, s.cfg.SessionAbsoluteTimeout)
	if err != nil {
		return nil, err
	}
	s.setSessionCookie(w, tok, sess.ExpiresAt)
	resp := &sessionResp{Authenticated: mfaVerified, MFARequired: !mfaVerified, CSRFToken: csrf}
	if mfaVerified {
		if resp.User, err = s.view(r.Context(), u); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) error {
	sess, u := sessionFrom(r.Context()), userFrom(r.Context())
	if sess == nil || u == nil {
		httpx.WriteJSON(w, http.StatusOK, sessionResp{Authenticated: false})
		return nil
	}
	resp := sessionResp{CSRFToken: sess.CSRFToken}
	if u.MFAEnabledAt != nil && !sess.MFAVerified {
		resp.MFARequired = true
	} else {
		resp.Authenticated = true
		v, err := s.view(r.Context(), u)
		if err != nil {
			return err
		}
		resp.User = v
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
	return nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) error {
	if sess, u := sessionFrom(r.Context()), userFrom(r.Context()); sess != nil && u != nil {
		if _, err := s.store.RevokeSession(r.Context(), u.ID, sess.ID); err != nil {
			return err
		}
		s.auditReq(r, "auth.logout", "session", sess.ID, "success", nil)
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------------------

func (s *Server) forgotPassword(w http.ResponseWriter, r *http.Request) error {
	if err := s.rateLimit(r, "forgot:ip:"+s.ip(r), 10, time.Hour); err != nil {
		return err
	}
	var req emailReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if email, ok := normalizeEmail(req.Email); ok {
		if okEmail, _, _ := s.limiter.Allow(r.Context(), "forgot:email:"+email, 3, time.Hour); okEmail {
			if u, err := s.store.UserByEmail(r.Context(), email); err == nil && u.Status == "active" {
				tok, err := auth.NewToken(32)
				if err != nil {
					return err
				}
				if err := s.store.CreateUserToken(r.Context(), u.ID, "password_reset", auth.HashToken(tok), resetTokenTTL); err != nil {
					return err
				}
				s.sendMail(r.Context(), rbmail.Message{To: u.Email, Subject: "Reset your ReverseBug password",
					Text: fmt.Sprintf("A password reset was requested for your ReverseBug account.\n\n%s/reset-password?token=%s\n\n"+
						"This link expires in 30 minutes and can be used once. If you did not request it, ignore this message.\n",
						s.cfg.PublicBaseURL, tok)})
				s.auditWrite(r.Context(), audit.Event{ActorType: "anonymous", Action: "auth.password_reset_requested",
					TargetType: "user", TargetID: u.ID, Outcome: "success", IP: s.ip(r), UserAgent: r.UserAgent()})
			}
		}
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "reset_sent_if_account_exists"})
	return nil
}

type resetReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) error {
	if err := s.rateLimit(r, "reset:ip:"+s.ip(r), 20, time.Hour); err != nil {
		return err
	}
	var req resetReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	invalid := httpx.NewError(http.StatusBadRequest, "invalid_token", "This reset link is invalid or has expired.")
	if req.Token == "" || len(req.Token) > 128 {
		return invalid
	}
	// Validate the policy before consuming the token so users can retry.
	if err := auth.ValidatePasswordPolicy(req.Password, ""); err != nil {
		return httpx.Validation(map[string]string{"password": err.Error()})
	}
	uid, err := s.store.ConsumeUserToken(r.Context(), "password_reset", auth.HashToken(req.Token))
	if errors.Is(err, store.ErrNotFound) {
		return invalid
	}
	if err != nil {
		return err
	}
	u, err := s.store.UserByID(r.Context(), uid)
	if err != nil {
		return err
	}
	if err := auth.ValidatePasswordPolicy(req.Password, u.Email); err != nil {
		return httpx.Validation(map[string]string{"password": err.Error()})
	}
	hash, err := auth.HashPassword(req.Password, s.argon)
	if err != nil {
		return err
	}
	if err := s.store.UpdatePasswordHash(r.Context(), uid, hash); err != nil {
		return err
	}
	_ = s.store.RecordLoginSuccess(r.Context(), uid) // clears lockout
	n, _ := s.store.RevokeUserSessions(r.Context(), uid, "")
	// Completing a reset proves mailbox control.
	_ = s.store.MarkEmailVerified(r.Context(), uid)
	s.auditWrite(r.Context(), audit.Event{ActorType: "user", ActorUserID: &uid, Action: "auth.password_reset",
		TargetType: "user", TargetID: uid, Outcome: "success", IP: s.ip(r), UserAgent: r.UserAgent(),
		Metadata: map[string]any{"sessions_revoked": n}})
	s.sendMail(r.Context(), rbmail.Message{To: u.Email, Subject: "Your ReverseBug password was changed",
		Text: "Your password was reset and all sessions were signed out. If this was not you, reset your password immediately and contact support.\n"})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
	return nil
}

// ---------------------------------------------------------------------------

type codeReq struct {
	Code     string `json:"code"`
	Password string `json:"password,omitempty"`
}

func (s *Server) totpSecret(u *store.User) (string, error) {
	if len(u.MFASecretEnc) == 0 {
		return "", errors.New("no totp secret")
	}
	b, err := s.sealer.Open(u.MFASecretEnc, []byte(u.ID))
	return string(b), err
}

// checkTOTP validates a code and enforces single use within the validity window.
func (s *Server) checkTOTP(ctx context.Context, u *store.User, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false, nil
	}
	secret, err := s.totpSecret(u)
	if err != nil {
		return false, err
	}
	if !auth.ValidateTOTP(code, secret, s.now()) {
		return false, nil
	}
	return s.limiter.Once(ctx, "totp:"+u.ID+":"+code, 2*time.Minute)
}

func (s *Server) mfaVerify(w http.ResponseWriter, r *http.Request) error {
	sess, u := sessionFrom(r.Context()), userFrom(r.Context())
	if u.MFAEnabledAt == nil || sess.MFAVerified {
		return s.session(w, r)
	}
	if err := s.rateLimit(r, "mfa:user:"+u.ID, 10, 15*time.Minute); err != nil {
		return err
	}
	var req codeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ok, err := s.checkTOTP(r.Context(), u, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		s.auditReq(r, "auth.mfa_verify", "user", u.ID, "failure", nil)
		return httpx.NewError(http.StatusUnauthorized, "invalid_mfa_code", "The verification code is incorrect or was already used.")
	}
	if err := s.store.MarkSessionMFAVerified(r.Context(), sess.ID); err != nil {
		return err
	}
	sess.MFAVerified = true
	s.auditReq(r, "auth.mfa_verify", "user", u.ID, "success", nil)
	return s.session(w, r)
}
