package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrSubscriptionNotFound = errors.New("subscription not found")
	ErrPlanNotFound         = errors.New("plan not found")
)

type Subscription struct {
	ID                     string     `json:"id"`
	OrganizationID         string     `json:"organization_id"`
	PlanID                 string     `json:"plan_id"`
	PlanVersion            int        `json:"plan_version"`
	Status                 string     `json:"status"`
	Provider               string     `json:"provider"`
	ProviderSubscriptionID *string    `json:"provider_subscription_id,omitempty"`
	CurrentPeriodStart     time.Time  `json:"current_period_start"`
	CurrentPeriodEnd       time.Time  `json:"current_period_end"`
	CancelAtPeriodEnd      bool       `json:"cancel_at_period_end"`
	GraceUntil             *time.Time `json:"grace_until,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

type SubscriptionDetail struct {
	Subscription
	PlanName     string            `json:"plan_name"`
	PriceCents   int               `json:"price_cents"`
	Currency     string            `json:"currency"`
	Interval     string            `json:"interval"`
	Entitlements map[string]*int64 `json:"entitlements"`
	Usage        map[string]int64  `json:"usage"`
}

// GetSubscription retrieves active subscription and entitlements for an organization.
func (s *Store) GetSubscription(ctx context.Context, orgID string) (*SubscriptionDetail, error) {
	var sub SubscriptionDetail
	err := s.Pool.QueryRow(ctx, `
		SELECT s.id, s.organization_id, s.plan_id, s.plan_version, s.status, s.provider,
		       s.provider_subscription_id, s.current_period_start, s.current_period_end,
		       s.cancel_at_period_end, s.grace_until, s.created_at, s.updated_at,
		       p.name, p.price_cents, p.currency, p.interval
		FROM subscriptions s
		JOIN plans p ON p.id = s.plan_id AND p.version = s.plan_version
		WHERE s.organization_id = $1 AND s.status IN ('active','trialing','past_due','grace')
		ORDER BY s.created_at DESC
		LIMIT 1;
	`, orgID).Scan(
		&sub.ID, &sub.OrganizationID, &sub.PlanID, &sub.PlanVersion, &sub.Status, &sub.Provider,
		&sub.ProviderSubscriptionID, &sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.CancelAtPeriodEnd, &sub.GraceUntil, &sub.CreatedAt, &sub.UpdatedAt,
		&sub.PlanName, &sub.PriceCents, &sub.Currency, &sub.Interval,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		// Auto-provision Free plan subscription if none exists
		return s.provisionDefaultFree(ctx, orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("get subscription: %w", err)
	}

	// Fetch entitlements
	sub.Entitlements = make(map[string]*int64)
	eRows, err := s.Pool.Query(ctx, `
		SELECT key, limit_value
		FROM entitlements
		WHERE plan_id = $1 AND plan_version = $2 AND enabled;
	`, sub.PlanID, sub.PlanVersion)
	if err == nil {
		defer eRows.Close()
		for eRows.Next() {
			var k string
			var limit *int64
			if err := eRows.Scan(&k, &limit); err == nil {
				sub.Entitlements[k] = limit
			}
		}
	}

	// Calculate usage for current period (scans count)
	sub.Usage = make(map[string]int64)
	var scanCount int64
	_ = s.Pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM scans sc
		JOIN projects pr ON pr.id = sc.project_id
		WHERE pr.organization_id = $1 AND sc.created_at >= $2;
	`, orgID, sub.CurrentPeriodStart).Scan(&scanCount)
	sub.Usage["scans_this_period"] = scanCount

	return &sub, nil
}

func (s *Store) provisionDefaultFree(ctx context.Context, orgID string) (*SubscriptionDetail, error) {
	// Find latest active 'free' plan
	var planID string
	var planVersion, priceCents int
	var name, currency, interval string
	err := s.Pool.QueryRow(ctx, `
		SELECT id, version, name, price_cents, currency, interval
		FROM plans
		WHERE id = 'free' AND is_active
		ORDER BY version DESC
		LIMIT 1;
	`).Scan(&planID, &planVersion, &name, &priceCents, &currency, &interval)
	if err != nil {
		return nil, fmt.Errorf("lookup free plan: %w", err)
	}

	now := time.Now().UTC()
	periodEnd := now.AddDate(1, 0, 0) // 1 year free period

	var subID string
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO subscriptions (
			organization_id, plan_id, plan_version, status, provider,
			current_period_start, current_period_end
		) VALUES ($1, $2, $3, 'active', 'none', $4, $5)
		RETURNING id;
	`, orgID, planID, planVersion, now, periodEnd).Scan(&subID)
	if err != nil {
		return nil, fmt.Errorf("provision free subscription: %w", err)
	}

	return s.GetSubscription(ctx, orgID)
}

// UpgradeSubscription transitions an organization to a new plan tier.
func (s *Store) UpgradeSubscription(ctx context.Context, orgID, planID string) (*SubscriptionDetail, error) {
	var planVersion int
	err := s.Pool.QueryRow(ctx, `
		SELECT version
		FROM plans
		WHERE id = $1 AND is_active
		ORDER BY version DESC
		LIMIT 1;
	`, planID).Scan(&planVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPlanNotFound
		}
		return nil, err
	}

	now := time.Now().UTC()
	periodEnd := now.AddDate(0, 1, 0) // 1 month period

	// Expire old active subscription
	_, _ = s.Pool.Exec(ctx, `
		UPDATE subscriptions
		SET status = 'expired', updated_at = now()
		WHERE organization_id = $1 AND status IN ('active','trialing','past_due','grace');
	`, orgID)

	// Create new active subscription
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO subscriptions (
			organization_id, plan_id, plan_version, status, provider,
			current_period_start, current_period_end
		) VALUES ($1, $2, $3, 'active', 'internal_billing', $4, $5);
	`, orgID, planID, planVersion, now, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("create upgraded subscription: %w", err)
	}

	return s.GetSubscription(ctx, orgID)
}

// CancelSubscription marks subscription to cancel at the end of current period.
func (s *Store) CancelSubscription(ctx context.Context, orgID string) error {
	cmd, err := s.Pool.Exec(ctx, `
		UPDATE subscriptions
		SET cancel_at_period_end = true, updated_at = now()
		WHERE organization_id = $1 AND status IN ('active','trialing','past_due','grace');
	`, orgID)
	if err != nil {
		return fmt.Errorf("cancel subscription: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrSubscriptionNotFound
	}
	return nil
}
