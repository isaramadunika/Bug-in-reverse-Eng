package store

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
)

type Session struct {
	ID            string    `json:"id"`
	UserID        string    `json:"-"`
	CSRFToken     string    `json:"-"`
	MFAVerified   bool      `json:"mfa_verified"`
	IP            *string   `json:"ip_address"`
	UserAgent     *string   `json:"user_agent"`
	CreatedAt     time.Time `json:"created_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	IdleExpiresAt time.Time `json:"-"`
	ExpiresAt     time.Time `json:"expires_at"`
	Current       bool      `json:"current"`
}

func ipOrNil(ip string) *string {
	if p := net.ParseIP(ip); p != nil {
		s := p.String()
		return &s
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, userID string, tokenHash []byte, csrf string,
	mfaVerified bool, ip, ua string, idle, absolute time.Duration) (*Session, error) {
	if len(ua) > 512 {
		ua = ua[:512]
	}
	var sess Session
	err := s.Pool.QueryRow(ctx, `INSERT INTO sessions (user_id, token_hash, csrf_token, mfa_verified,
		ip_address, user_agent, idle_expires_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6, now() + $7::interval, now() + $8::interval)
		RETURNING id, user_id, csrf_token, mfa_verified, host(ip_address), user_agent, created_at, last_seen_at, idle_expires_at, expires_at`,
		userID, tokenHash, csrf, mfaVerified, ipOrNil(ip), ua, idle.String(), absolute.String()).
		Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &sess.MFAVerified, &sess.IP, &sess.UserAgent,
			&sess.CreatedAt, &sess.LastSeenAt, &sess.IdleExpiresAt, &sess.ExpiresAt)
	return &sess, err
}

// SessionByToken returns a live session and slides its idle expiry. Expired,
// revoked or suspended-account sessions are treated as not found.
func (s *Store) SessionByToken(ctx context.Context, tokenHash []byte, idle time.Duration) (*Session, error) {
	var sess Session
	err := s.Pool.QueryRow(ctx, `UPDATE sessions s SET last_seen_at = now(),
			idle_expires_at = LEAST(now() + $2::interval, s.expires_at)
		FROM users u
		WHERE s.token_hash = $1 AND s.user_id = u.id AND s.revoked_at IS NULL
		  AND s.expires_at > now() AND s.idle_expires_at > now() AND u.status = 'active'
		RETURNING s.id, s.user_id, s.csrf_token, s.mfa_verified, host(s.ip_address), s.user_agent,
		  s.created_at, s.last_seen_at, s.idle_expires_at, s.expires_at`, tokenHash, idle.String()).
		Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &sess.MFAVerified, &sess.IP, &sess.UserAgent,
			&sess.CreatedAt, &sess.LastSeenAt, &sess.IdleExpiresAt, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &sess, err
}

func (s *Store) MarkSessionMFAVerified(ctx context.Context, sessionID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET mfa_verified = true WHERE id = $1`, sessionID)
	return err
}

func (s *Store) RevokeSession(ctx context.Context, userID, sessionID string) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at = now()
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, sessionID, userID)
	return tag.RowsAffected() > 0, err
}

// RevokeUserSessions revokes all sessions for the user except `keep` (may be empty).
func (s *Store) RevokeUserSessions(ctx context.Context, userID, keep string) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE sessions SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL AND ($2 = '' OR id::text <> $2)`, userID, keep)
	return tag.RowsAffected(), err
}

func (s *Store) ListSessions(ctx context.Context, userID, currentID string) ([]Session, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, mfa_verified, host(ip_address), user_agent, created_at, last_seen_at, expires_at
		FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now()
		ORDER BY last_seen_at DESC LIMIT 50`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Session, error) {
		var x Session
		err := r.Scan(&x.ID, &x.MFAVerified, &x.IP, &x.UserAgent, &x.CreatedAt, &x.LastSeenAt, &x.ExpiresAt)
		x.Current = x.ID == currentID
		return x, err
	})
}

// ---- single-use user tokens ----

func (s *Store) CreateUserToken(ctx context.Context, userID, purpose string, tokenHash []byte, ttl time.Duration) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// Invalidate earlier unused tokens of the same purpose.
		if _, err := tx.Exec(ctx, `UPDATE user_tokens SET used_at = now()
			WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL`, userID, purpose); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO user_tokens (user_id, purpose, token_hash, expires_at)
			VALUES ($1,$2,$3, now() + $4::interval)`, userID, purpose, tokenHash, ttl.String())
		return err
	})
}

// ConsumeUserToken atomically marks a valid token used and returns its user id.
func (s *Store) ConsumeUserToken(ctx context.Context, purpose string, tokenHash []byte) (string, error) {
	var userID string
	err := s.Pool.QueryRow(ctx, `UPDATE user_tokens SET used_at = now()
		WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
		RETURNING user_id`, tokenHash, purpose).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return userID, err
}
