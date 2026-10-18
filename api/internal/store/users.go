// Package store contains PostgreSQL data access. All tenant-scoped queries take
// the caller's identity and enforce ownership in SQL.
package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrEmailTaken = errors.New("email already registered")
)

type Store struct{ Pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

type User struct {
	ID                    string     `json:"id"`
	Email                 string     `json:"email"`
	DisplayName           string     `json:"display_name"`
	PasswordHash          string     `json:"-"`
	EmailVerifiedAt       *time.Time `json:"email_verified_at"`
	PlatformRole          string     `json:"platform_role"`
	Status                string     `json:"status"`
	MFASecretEnc          []byte     `json:"-"`
	MFAEnabledAt          *time.Time `json:"mfa_enabled_at"`
	OnboardingCompletedAt *time.Time `json:"onboarding_completed_at"`
	OnboardingStep        int        `json:"onboarding_step"`
	ThemePreference       string     `json:"theme_preference"`
	FailedLoginCount      int        `json:"-"`
	LockedUntil           *time.Time `json:"-"`
	LastLoginAt           *time.Time `json:"last_login_at"`
	CreatedAt             time.Time  `json:"created_at"`
}

const userCols = `id, email, display_name, password_hash, email_verified_at, platform_role, status,
	mfa_totp_secret_enc, mfa_enabled_at, onboarding_completed_at, onboarding_step, theme_preference,
	failed_login_count, locked_until, last_login_at, created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.EmailVerifiedAt, &u.PlatformRole,
		&u.Status, &u.MFASecretEnc, &u.MFAEnabledAt, &u.OnboardingCompletedAt, &u.OnboardingStep,
		&u.ThemePreference, &u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE email = $1`, email))
}

func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = s[:40]
	}
	if s == "" {
		s = "workspace"
	}
	return s
}

// CreateUser creates the user, a personal organization, owner membership and a
// Free subscription in one transaction.
func (s *Store) CreateUser(ctx context.Context, email, name, hash string) (*User, string, error) {
	var u *User
	var orgID string
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		u, err = scanUser(tx.QueryRow(ctx, `INSERT INTO users (email, display_name, password_hash)
			VALUES ($1,$2,$3) RETURNING `+userCols, email, name, hash))
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrEmailTaken
			}
			return err
		}
		slug := fmt.Sprintf("%s-%s", slugify(name), u.ID[:8])
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name, slug, is_personal, created_by)
			VALUES ($1,$2,true,$3) RETURNING id`, name+"'s workspace", slug, u.ID).Scan(&orgID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO organization_members (organization_id, user_id, role)
			VALUES ($1,$2,'owner')`, orgID, u.ID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO subscriptions (organization_id, plan_id, plan_version, status,
			current_period_start, current_period_end)
			SELECT $1, id, version, 'active', date_trunc('month', now()), date_trunc('month', now()) + interval '1 month'
			FROM plans WHERE id = 'free' AND is_active ORDER BY version DESC LIMIT 1`, orgID)
		return err
	})
	return u, orgID, err
}

// RecordLoginFailure increments the counter and locks the account temporarily
// after repeated failures. Returns the resulting lock time, if any.
func (s *Store) RecordLoginFailure(ctx context.Context, userID string, threshold int, lockFor time.Duration) (*time.Time, error) {
	var locked *time.Time
	err := s.Pool.QueryRow(ctx, `UPDATE users SET
		failed_login_count = failed_login_count + 1,
		locked_until = CASE WHEN failed_login_count + 1 >= $2 THEN now() + $3::interval ELSE locked_until END,
		updated_at = now()
		WHERE id = $1 RETURNING locked_until`, userID, threshold, lockFor.String()).Scan(&locked)
	return locked, err
}

func (s *Store) RecordLoginSuccess(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET failed_login_count = 0, locked_until = NULL,
		last_login_at = now(), updated_at = now() WHERE id = $1`, userID)
	return err
}

func (s *Store) UpdatePasswordHash(ctx context.Context, userID, hash string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, userID, hash)
	return err
}

func (s *Store) MarkEmailVerified(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()),
		updated_at = now() WHERE id = $1`, userID)
	return err
}

func (s *Store) UpdateProfile(ctx context.Context, userID string, name, theme *string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET display_name = COALESCE($2, display_name),
		theme_preference = COALESCE($3, theme_preference), updated_at = now() WHERE id = $1`, userID, name, theme)
	return err
}

func (s *Store) SetOnboarding(ctx context.Context, userID string, step int, completed bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET onboarding_step = $2,
		onboarding_completed_at = CASE WHEN $3 THEN COALESCE(onboarding_completed_at, now()) ELSE onboarding_completed_at END,
		updated_at = now() WHERE id = $1`, userID, step, completed)
	return err
}

func (s *Store) ResetOnboarding(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET onboarding_step = 0, onboarding_completed_at = NULL,
		updated_at = now() WHERE id = $1`, userID)
	return err
}

func (s *Store) SetPendingTOTP(ctx context.Context, userID string, enc []byte) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET mfa_totp_secret_enc = $2, updated_at = now()
		WHERE id = $1 AND mfa_enabled_at IS NULL`, userID, enc)
	return err
}

func (s *Store) EnableMFA(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET mfa_enabled_at = now(), updated_at = now()
		WHERE id = $1 AND mfa_totp_secret_enc IS NOT NULL`, userID)
	return err
}

func (s *Store) DisableMFA(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET mfa_enabled_at = NULL, mfa_totp_secret_enc = NULL,
		updated_at = now() WHERE id = $1`, userID)
	return err
}

func (s *Store) RequestDeletion(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET status = 'pending_deletion', deletion_requested_at = now(),
		updated_at = now() WHERE id = $1`, userID)
	return err
}

// SetPlatformRole is used only by the operator CLI bootstrap procedure.
func (s *Store) SetPlatformRole(ctx context.Context, email, role string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `UPDATE users SET platform_role = $2, updated_at = now()
		WHERE email = $1 AND status = 'active' AND email_verified_at IS NOT NULL RETURNING id`, email, role).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

type Membership struct {
	OrgID      string `json:"organization_id"`
	OrgName    string `json:"organization_name"`
	Role       string `json:"role"`
	IsPersonal bool   `json:"is_personal"`
	PlanID     string `json:"plan_id"`
	PlanName   string `json:"plan_name"`
}

func (s *Store) Memberships(ctx context.Context, userID string) ([]Membership, error) {
	rows, err := s.Pool.Query(ctx, `SELECT o.id, o.name, m.role, o.is_personal,
		COALESCE(p.id, 'free'), COALESCE(p.name, 'Free')
		FROM organization_members m
		JOIN organizations o ON o.id = m.organization_id
		LEFT JOIN subscriptions sub ON sub.organization_id = o.id AND sub.status IN ('active','trialing','past_due','grace')
		LEFT JOIN plans p ON p.id = sub.plan_id AND p.version = sub.plan_version
		WHERE m.user_id = $1 ORDER BY o.is_personal DESC, o.created_at`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Membership, error) {
		var m Membership
		err := r.Scan(&m.OrgID, &m.OrgName, &m.Role, &m.IsPersonal, &m.PlanID, &m.PlanName)
		return m, err
	})
}
