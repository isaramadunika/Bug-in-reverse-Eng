package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type PublicPlan struct {
	ID           string            `json:"id"`
	Version      int               `json:"version"`
	Name         string            `json:"name"`
	Rank         int               `json:"rank"`
	PriceCents   int               `json:"price_cents"`
	Currency     string            `json:"currency"`
	Interval     string            `json:"interval"`
	Entitlements map[string]*int64 `json:"entitlements"`
}

// PublicPlans returns the latest active, public version of each plan.
func (s *Store) PublicPlans(ctx context.Context) ([]PublicPlan, error) {
	rows, err := s.Pool.Query(ctx, `
		WITH latest AS (
		  SELECT DISTINCT ON (id) id, version, name, rank, price_cents, currency, interval
		  FROM plans WHERE is_active AND is_public ORDER BY id, version DESC)
		SELECT l.id, l.version, l.name, l.rank, l.price_cents, l.currency, l.interval, e.key, e.limit_value
		FROM latest l LEFT JOIN entitlements e ON e.plan_id = l.id AND e.plan_version = l.version AND e.enabled
		ORDER BY l.rank, e.key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublicPlan
	idx := map[string]int{}
	for rows.Next() {
		var p PublicPlan
		var key *string
		var limit *int64
		if err := rows.Scan(&p.ID, &p.Version, &p.Name, &p.Rank, &p.PriceCents, &p.Currency, &p.Interval, &key, &limit); err != nil {
			return nil, err
		}
		i, ok := idx[p.ID]
		if !ok {
			p.Entitlements = map[string]*int64{}
			out = append(out, p)
			i = len(out) - 1
			idx[p.ID] = i
		}
		if key != nil {
			out[i].Entitlements[*key] = limit
		}
	}
	return out, rows.Err()
}

type CountPoint struct {
	Day   string `json:"day"`
	Value int64  `json:"value"`
}

type ScorePoint struct {
	ScanID    string    `json:"scan_id"`
	Project   string    `json:"project"`
	Score     int       `json:"score"`
	CreatedAt time.Time `json:"created_at"`
}

type ActivityItem struct {
	Action     string    `json:"action"`
	TargetType *string   `json:"target_type"`
	TargetID   *string   `json:"target_id"`
	Outcome    string    `json:"outcome"`
	OccurredAt time.Time `json:"occurred_at"`
}

type RecentScan struct {
	ID          string     `json:"id"`
	ProjectID   string     `json:"project_id"`
	ProjectName string     `json:"project_name"`
	Profile     string     `json:"profile"`
	Status      string     `json:"status"`
	Score       *int       `json:"security_score"`
	CreatedAt   time.Time  `json:"created_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	FailureReason *string  `json:"failure_reason"`
}

type DashboardSummary struct {
	Projects        int64            `json:"projects"`
	Scans           int64            `json:"scans"`
	Running         int64            `json:"running"`
	Queued          int64            `json:"queued"`
	Completed       int64            `json:"completed"`
	Failed          int64            `json:"failed"`
	Severity        map[string]int64 `json:"findings_by_severity"`
	Reports         int64            `json:"reports"`
	ScansPerDay     []CountPoint     `json:"scans_per_day"`
	AvgDurationSec  *float64         `json:"avg_scan_duration_seconds"`
	ScoreTrend      []ScorePoint     `json:"score_trend"`
	RecentScans     []RecentScan     `json:"recent_scans"`
	RecentActivity  []ActivityItem   `json:"recent_activity"`
	UsageScans      int64            `json:"usage_scans_this_period"`
	QuotaScans      *int64           `json:"quota_scans_per_month"`
	PlanName        string           `json:"plan_name"`
	RangeDays       int              `json:"range_days"`
}

// Dashboard computes all statistics from real rows visible to the user through
// organization membership. projectID optionally narrows the scope.
func (s *Store) Dashboard(ctx context.Context, userID string, days int, projectID *string) (*DashboardSummary, error) {
	d := &DashboardSummary{Severity: map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, RangeDays: days}
	scope := `WITH visible AS (
		SELECT p.id, p.name FROM projects p
		JOIN organization_members m ON m.organization_id = p.organization_id AND m.user_id = $1
		WHERE p.deleted_at IS NULL AND ($2::uuid IS NULL OR p.id = $2::uuid))`
	since := time.Now().AddDate(0, 0, -days)

	err := s.Pool.QueryRow(ctx, scope+`
		SELECT (SELECT count(*) FROM visible),
		  count(s.id) FILTER (WHERE s.created_at >= $3),
		  count(s.id) FILTER (WHERE s.status IN ('running','cancelling')),
		  count(s.id) FILTER (WHERE s.status = 'queued'),
		  count(s.id) FILTER (WHERE s.status = 'completed' AND s.created_at >= $3),
		  count(s.id) FILTER (WHERE s.status = 'failed' AND s.created_at >= $3),
		  avg(EXTRACT(EPOCH FROM s.finished_at - s.started_at)) FILTER (WHERE s.status = 'completed' AND s.created_at >= $3)
		FROM visible v LEFT JOIN scans s ON s.project_id = v.id`, userID, projectID, since).
		Scan(&d.Projects, &d.Scans, &d.Running, &d.Queued, &d.Completed, &d.Failed, &d.AvgDurationSec)
	if err != nil {
		return nil, err
	}

	rows, err := s.Pool.Query(ctx, scope+`
		SELECT f.severity, count(*) FROM visible v
		JOIN scans s ON s.project_id = v.id AND s.status = 'completed' AND s.created_at >= $3
		JOIN findings f ON f.scan_id = s.id AND f.duplicate_of IS NULL AND f.review_status <> 'false_positive'
		GROUP BY f.severity`, userID, projectID, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		d.Severity[sev] = n
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, scope+`
		SELECT to_char(day, 'YYYY-MM-DD'), count(s.id)
		FROM generate_series(date_trunc('day', $3::timestamptz), date_trunc('day', now()), interval '1 day') day
		LEFT JOIN scans s ON date_trunc('day', s.created_at) = day AND s.project_id IN (SELECT id FROM visible)
		GROUP BY day ORDER BY day`, userID, projectID, since)
	if err != nil {
		return nil, err
	}
	d.ScansPerDay, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (CountPoint, error) {
		var c CountPoint
		return c, r.Scan(&c.Day, &c.Value)
	})
	if err != nil {
		return nil, err
	}

	rows, err = s.Pool.Query(ctx, scope+`
		SELECT s.id, v.name, s.security_score, s.created_at FROM visible v
		JOIN scans s ON s.project_id = v.id
		WHERE s.status = 'completed' AND s.score_state = 'scored' AND s.created_at >= $3
		ORDER BY s.created_at LIMIT 200`, userID, projectID, since)
	if err != nil {
		return nil, err
	}
	d.ScoreTrend, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ScorePoint, error) {
		var p ScorePoint
		return p, r.Scan(&p.ScanID, &p.Project, &p.Score, &p.CreatedAt)
	})
	if err != nil {
		return nil, err
	}

	rows, err = s.Pool.Query(ctx, scope+`
		SELECT s.id, v.id, v.name, s.profile_id, s.status, s.security_score, s.created_at, s.finished_at, s.failure_reason
		FROM visible v JOIN scans s ON s.project_id = v.id ORDER BY s.created_at DESC LIMIT 8`, userID, projectID)
	if err != nil {
		return nil, err
	}
	d.RecentScans, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (RecentScan, error) {
		var x RecentScan
		return x, r.Scan(&x.ID, &x.ProjectID, &x.ProjectName, &x.Profile, &x.Status, &x.Score, &x.CreatedAt, &x.FinishedAt, &x.FailureReason)
	})
	if err != nil {
		return nil, err
	}

	if err := s.Pool.QueryRow(ctx, scope+`
		SELECT count(*) FROM visible v JOIN scans s ON s.project_id = v.id
		JOIN reports r ON r.scan_id = s.id AND r.status = 'ready'`, userID, projectID).Scan(&d.Reports); err != nil {
		return nil, err
	}

	rows, err = s.Pool.Query(ctx, `SELECT action, target_type, target_id, outcome, occurred_at
		FROM audit_events WHERE actor_user_id = $1 ORDER BY id DESC LIMIT 10`, userID)
	if err != nil {
		return nil, err
	}
	d.RecentActivity, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ActivityItem, error) {
		var a ActivityItem
		return a, r.Scan(&a.Action, &a.TargetType, &a.TargetID, &a.Outcome, &a.OccurredAt)
	})
	if err != nil {
		return nil, err
	}

	// Usage against the personal/primary organization's plan.
	err = s.Pool.QueryRow(ctx, `
		SELECT p.name,
		  (SELECT limit_value FROM entitlements e WHERE e.plan_id = p.id AND e.plan_version = p.version AND e.key = 'scans_per_month'),
		  COALESCE((SELECT value FROM usage_counters u WHERE u.organization_id = o.id
		            AND u.period_start = date_trunc('month', now())::date AND u.metric = 'scans'), 0)
		FROM organization_members m
		JOIN organizations o ON o.id = m.organization_id
		JOIN subscriptions sub ON sub.organization_id = o.id AND sub.status IN ('active','trialing','past_due','grace')
		JOIN plans p ON p.id = sub.plan_id AND p.version = sub.plan_version
		WHERE m.user_id = $1 ORDER BY o.is_personal DESC LIMIT 1`, userID).Scan(&d.PlanName, &d.QuotaScans, &d.UsageScans)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	return d, nil
}
