package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/tetraneurons/reversebug/api/internal/auth"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

type ctxKey int

const (
	sessionKey ctxKey = iota
	userKey
)

func (s *Server) cookieName() string {
	// The __Host- prefix forces Secure, Path=/ and no Domain attribute.
	if s.cfg.CookieSecure {
		return "__Host-rb_session"
	}
	return "rb_session"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
}

func sessionFrom(ctx context.Context) *store.Session {
	v, _ := ctx.Value(sessionKey).(*store.Session)
	return v
}

func userFrom(ctx context.Context) *store.User {
	v, _ := ctx.Value(userKey).(*store.User)
	return v
}

// loadSession resolves the session cookie, if present, into the request context.
func (s *Server) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.cookieName())
		if err != nil || c.Value == "" || len(c.Value) > 128 {
			next.ServeHTTP(w, r)
			return
		}
		sess, err := s.store.SessionByToken(r.Context(), auth.HashToken(c.Value), s.cfg.SessionIdleTimeout)
		if errors.Is(err, store.ErrNotFound) {
			s.clearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		u, err := s.store.UserByID(r.Context(), sess.UserID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		ctx = context.WithValue(ctx, userKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrfProtect applies to every state-changing request:
//  1. If an Origin header is present it must be allowlisted.
//  2. Cookie-authenticated requests must echo the session's CSRF token.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if httpx.IsSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
			httpx.WriteError(w, r, httpx.ErrCSRF)
			return
		}
		if sess := sessionFrom(r.Context()); sess != nil {
			got := r.Header.Get("X-CSRF-Token")
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
				httpx.WriteError(w, r, httpx.ErrCSRF)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	if slices.Contains(s.cfg.AllowedOrigins, origin) {
		return true
	}
	// Same-origin deployments (SPA served by the same host as the API).
	if u, err := url.Parse(origin); err == nil {
		if pb, err := url.Parse(s.cfg.PublicBaseURL); err == nil && u.Scheme == pb.Scheme && u.Host == pb.Host {
			return true
		}
	}
	return false
}

// requireSession allows sessions whose MFA step is still pending.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sessionFrom(r.Context()) == nil {
			httpx.WriteError(w, r, httpx.ErrUnauthenticated)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth requires a live session that has satisfied MFA if enrolled.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, u := sessionFrom(r.Context()), userFrom(r.Context())
		if sess == nil || u == nil {
			httpx.WriteError(w, r, httpx.ErrUnauthenticated)
			return
		}
		if u.MFAEnabledAt != nil && !sess.MFAVerified {
			httpx.WriteError(w, r, httpx.ErrMFARequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireVerifiedEmail(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := userFrom(r.Context()); u == nil || u.EmailVerifiedAt == nil {
			httpx.WriteError(w, r, httpx.ErrEmailUnverified)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAdmin enforces platform roles server-side. Privileged roles must have
// MFA enrolled and verified on the current session when AdminRequireMFA is set.
func (s *Server) requireAdmin(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, sess := userFrom(r.Context()), sessionFrom(r.Context())
			if u == nil || !slices.Contains(roles, u.PlatformRole) {
				s.auditReq(r, "admin.access", "route", r.URL.Path, "denied", nil)
				httpx.WriteError(w, r, httpx.ErrForbidden)
				return
			}
			if s.cfg.AdminRequireMFA && (u.MFAEnabledAt == nil || !sess.MFAVerified) {
				httpx.WriteError(w, r, httpx.NewError(http.StatusForbidden, "admin_mfa_required",
					"Administrators must enable and verify multi-factor authentication."))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimit applies a fixed-window limit; on limiter failure it fails closed
// for authentication endpoints.
func (s *Server) rateLimit(r *http.Request, key string, limit int, window time.Duration) error {
	ok, retry, err := s.limiter.Allow(r.Context(), key, limit, window)
	if err != nil {
		return httpx.NewError(http.StatusServiceUnavailable, "rate_limiter_unavailable", "Service temporarily unavailable.")
	}
	if !ok {
		e := *httpx.ErrRateLimited
		if retry > 0 {
			e.Message = "Too many attempts. Try again in " + retry.Round(time.Second).String() + "."
		}
		return &e
	}
	return nil
}
