package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrAPIKeyNotFound = errors.New("api key not found")
	ErrAPIKeyInvalid  = errors.New("invalid or revoked api key")
)

type APIKey struct {
	ID              string     `json:"id"`
	OrganizationID  string     `json:"organization_id"`
	UserID          string     `json:"user_id"`
	Name            string     `json:"name"`
	Prefix          string     `json:"prefix"`
	Scopes          []string   `json:"scopes"`
	UsageLimit      *int64     `json:"usage_limit,omitempty"`
	UsageCount      int64      `json:"usage_count"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP      *string    `json:"last_used_ip,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	RevokedBy       *string    `json:"revoked_by,omitempty"`
	DisabledByAdmin bool       `json:"disabled_by_admin"`
	CreatedAt       time.Time  `json:"created_at"`
}

func ComputeKeyHMAC(rawToken string, pepper []byte) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(rawToken))
	return mac.Sum(nil)
}

// CreateAPIKey generates a cryptographically secure random token and stores HMAC peppered record.
func (s *Store) CreateAPIKey(
	ctx context.Context,
	orgID string,
	userID string,
	name string,
	scopes []string,
	expiresAt *time.Time,
	pepper []byte,
) (string, *APIKey, error) {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 80 {
		return "", nil, fmt.Errorf("api key name must be between 1 and 80 characters")
	}

	if len(scopes) == 0 {
		scopes = []string{"scans:read", "scans:write", "projects:read", "reports:read"}
	}
	// Disallow admin scopes
	for _, sc := range scopes {
		if strings.HasPrefix(sc, "admin") {
			return "", nil, fmt.Errorf("admin scopes are not permitted for api keys")
		}
	}

	// Generate 24 random bytes -> 48 hex chars
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generate random bytes: %w", err)
	}
	randomHex := hex.EncodeToString(b)
	rawToken := fmt.Sprintf("rb_live_%s", randomHex)
	prefix := fmt.Sprintf("rb_live_%s", randomHex[:8])

	secretHMAC := ComputeKeyHMAC(rawToken, pepper)

	var k APIKey
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO api_keys (
			organization_id, user_id, name, prefix, secret_hmac, scopes, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, organization_id, user_id, name, prefix, scopes, usage_count, expires_at, created_at;
	`, orgID, userID, name, prefix, secretHMAC, scopes, expiresAt).Scan(
		&k.ID, &k.OrganizationID, &k.UserID, &k.Name, &k.Prefix,
		&k.Scopes, &k.UsageCount, &k.ExpiresAt, &k.CreatedAt,
	)
	if err != nil {
		return "", nil, fmt.Errorf("insert api key: %w", err)
	}

	return rawToken, &k, nil
}

// ListAPIKeys retrieves all API keys for an organization.
func (s *Store) ListAPIKeys(ctx context.Context, orgID string) ([]APIKey, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, organization_id, user_id, name, prefix, scopes, usage_limit, usage_count,
		       expires_at, last_used_at, last_used_ip, revoked_at, revoked_by, disabled_by_admin, created_at
		FROM api_keys
		WHERE organization_id = $1
		ORDER BY created_at DESC;
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		var ip *net.IPNet
		if err := rows.Scan(
			&k.ID, &k.OrganizationID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
			&k.UsageLimit, &k.UsageCount, &k.ExpiresAt, &k.LastUsedAt, &ip,
			&k.RevokedAt, &k.RevokedBy, &k.DisabledByAdmin, &k.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		if ip != nil {
			ipStr := ip.IP.String()
			k.LastUsedIP = &ipStr
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// RevokeAPIKey marks an API key as revoked.
func (s *Store) RevokeAPIKey(ctx context.Context, orgID, keyID, revokedBy string) error {
	cmd, err := s.Pool.Exec(ctx, `
		UPDATE api_keys
		SET revoked_at = now(),
		    revoked_by = $1
		WHERE id = $2 AND organization_id = $3 AND revoked_at IS NULL;
	`, revokedBy, keyID, orgID)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

// AuthenticateAPIKey verifies the raw token using timing-safe HMAC comparison.
func (s *Store) AuthenticateAPIKey(ctx context.Context, rawToken string, pepper []byte, clientIP string) (*APIKey, *User, error) {
	rawToken = strings.TrimSpace(rawToken)
	if !strings.HasPrefix(rawToken, "rb_live_") || len(rawToken) < 16 {
		return nil, nil, ErrAPIKeyInvalid
	}

	prefix := rawToken[:16] // e.g. "rb_live_" + 8 chars
	var k APIKey
	var storedHMAC []byte
	var u User

	err := s.Pool.QueryRow(ctx, `
		SELECT k.id, k.organization_id, k.user_id, k.name, k.prefix, k.secret_hmac, k.scopes,
		       k.usage_limit, k.usage_count, k.expires_at, k.last_used_at, k.revoked_at,
		       k.disabled_by_admin, k.created_at,
		       u.id, u.email, u.display_name, u.platform_role, u.status, u.email_verified_at, u.mfa_enabled_at
		FROM api_keys k
		JOIN users u ON u.id = k.user_id
		WHERE k.prefix = $1;
	`, prefix).Scan(
		&k.ID, &k.OrganizationID, &k.UserID, &k.Name, &k.Prefix, &storedHMAC, &k.Scopes,
		&k.UsageLimit, &k.UsageCount, &k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt,
		&k.DisabledByAdmin, &k.CreatedAt,
		&u.ID, &u.Email, &u.DisplayName, &u.PlatformRole, &u.Status, &u.EmailVerifiedAt, &u.MFAEnabledAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrAPIKeyInvalid
		}
		return nil, nil, err
	}

	// Active checks
	if k.RevokedAt != nil || k.DisabledByAdmin {
		return nil, nil, ErrAPIKeyInvalid
	}
	if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now()) {
		return nil, nil, ErrAPIKeyInvalid
	}
	if u.Status != "active" {
		return nil, nil, ErrAPIKeyInvalid
	}

	// Timing-safe HMAC verification
	calculatedHMAC := ComputeKeyHMAC(rawToken, pepper)
	if !hmac.Equal(calculatedHMAC, storedHMAC) {
		return nil, nil, ErrAPIKeyInvalid
	}

	// Update last used asynchronously or inline
	var ipParam any
	if clientIP != "" {
		if parsed := net.ParseIP(clientIP); parsed != nil {
			ipParam = parsed.String()
		}
	}
	_, _ = s.Pool.Exec(ctx, `
		UPDATE api_keys
		SET last_used_at = now(),
		    last_used_ip = $1,
		    usage_count = usage_count + 1
		WHERE id = $2;
	`, ipParam, k.ID)

	return &k, &u, nil
}
