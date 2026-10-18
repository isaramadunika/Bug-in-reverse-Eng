// Package server wires routes, middleware and handlers for /api/v1.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/auth"
	"github.com/tetraneurons/reversebug/api/internal/config"
	"github.com/tetraneurons/reversebug/api/internal/httpx"
	"github.com/tetraneurons/reversebug/api/internal/mail"
	"github.com/tetraneurons/reversebug/api/internal/ratelimit"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

type Server struct {
	cfg     *config.Config
	store   *store.Store
	audit   *audit.Logger
	mailer  mail.Mailer
	limiter ratelimit.Limiter
	sealer  *auth.Sealer
	argon   auth.Argon2Params
	now     func() time.Time
	// mailWG lets tests wait for asynchronous email delivery.
	sendMail func(ctx context.Context, m mail.Message)
}

type Deps struct {
	Config  *config.Config
	Store   *store.Store
	Audit   *audit.Logger
	Mailer  mail.Mailer
	Limiter ratelimit.Limiter
	Argon   *auth.Argon2Params
	// SyncMail sends email inline (tests). Production sends in the background so
	// response timing does not reveal whether an account exists.
	SyncMail bool
}

func New(d Deps) (*Server, error) {
	sealer, err := auth.NewSealer(d.Config.DataEncryptionKey)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: d.Config, store: d.Store, audit: d.Audit, mailer: d.Mailer, limiter: d.Limiter,
		sealer: sealer, argon: auth.DefaultArgon2, now: time.Now}
	if d.Argon != nil {
		s.argon = *d.Argon
	}
	s.sendMail = func(ctx context.Context, m mail.Message) {
		deliver := func(ctx context.Context) {
			if err := s.mailer.Send(ctx, m); err != nil {
				slog.Error("email delivery failed", "err", err, "subject", m.Subject)
			}
		}
		if d.SyncMail {
			deliver(ctx)
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			deliver(ctx)
		}()
	}
	return s, nil
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(httpx.RequestIDMiddleware, httpx.Recoverer, httpx.Logging,
		httpx.SecurityHeaders(s.cfg.CookieSecure), httpx.CORS(s.cfg.AllowedOrigins))

	r.Get("/healthz", s.healthz)
	r.Get("/readyz", s.readyz)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.loadSession, s.csrfProtect)
		r.NotFound(httpx.Handler(func(w http.ResponseWriter, r *http.Request) error { return httpx.ErrNotFound }).ServeHTTP)

		r.Get("/public/plans", httpx.Handler(s.publicPlans).ServeHTTP)

		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", httpx.Handler(s.register).ServeHTTP)
			r.Post("/login", httpx.Handler(s.login).ServeHTTP)
			r.Post("/logout", httpx.Handler(s.logout).ServeHTTP)
			r.Get("/session", httpx.Handler(s.session).ServeHTTP)
			r.Post("/verify-email", httpx.Handler(s.verifyEmail).ServeHTTP)
			r.Post("/verify-email/resend", httpx.Handler(s.resendVerification).ServeHTTP)
			r.Post("/password/forgot", httpx.Handler(s.forgotPassword).ServeHTTP)
			r.Post("/password/reset", httpx.Handler(s.resetPassword).ServeHTTP)
			r.With(s.requireSession).Post("/mfa/verify", httpx.Handler(s.mfaVerify).ServeHTTP)
		})

		// Authenticated, MFA-satisfied routes.
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Get("/me", httpx.Handler(s.me).ServeHTTP)
			r.Patch("/me", httpx.Handler(s.updateMe).ServeHTTP)
			r.Post("/me/password", httpx.Handler(s.changePassword).ServeHTTP)
			r.Put("/me/onboarding", httpx.Handler(s.updateOnboarding).ServeHTTP)
			r.Post("/me/onboarding/replay", httpx.Handler(s.replayOnboarding).ServeHTTP)
			r.Get("/me/sessions", httpx.Handler(s.listSessions).ServeHTTP)
			r.Delete("/me/sessions/{sessionID}", httpx.Handler(s.revokeSession).ServeHTTP)
			r.Post("/me/sessions/revoke-others", httpx.Handler(s.revokeOtherSessions).ServeHTTP)
			r.Post("/me/mfa/totp/setup", httpx.Handler(s.mfaSetup).ServeHTTP)
			r.Post("/me/mfa/totp/enable", httpx.Handler(s.mfaEnable).ServeHTTP)
			r.Post("/me/mfa/totp/disable", httpx.Handler(s.mfaDisable).ServeHTTP)
			r.Get("/me/export", httpx.Handler(s.exportAccount).ServeHTTP)
			r.Post("/me/deletion", httpx.Handler(s.requestDeletion).ServeHTTP)

			r.Group(func(r chi.Router) {
				r.Use(s.requireVerifiedEmail)
				r.Get("/dashboard/summary", httpx.Handler(s.dashboard).ServeHTTP)
			})

			r.Route("/admin", func(r chi.Router) {
				r.Use(s.requireAdmin("support_admin", "billing_admin", "system_admin"))
				r.Get("/audit/verify", httpx.Handler(s.adminVerifyAudit).ServeHTTP)
			})
		})
	})
	return r
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	checks := map[string]string{"database": "ok", "rate_limiter": "ok"}
	status := http.StatusOK
	if err := s.store.Pool.Ping(ctx); err != nil {
		checks["database"] = "unavailable"
		status = http.StatusServiceUnavailable
	}
	if err := s.limiter.Ping(ctx); err != nil {
		checks["rate_limiter"] = "unavailable"
		status = http.StatusServiceUnavailable
	}
	httpx.WriteJSON(w, status, checks)
}
