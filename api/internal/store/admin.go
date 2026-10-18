package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type AdminUserFilter struct {
	Search       string `json:"search"`
	Status       string `json:"status"`
	PlatformRole string `json:"platform_role"`
	Limit        int    `json:"limit"`
	Offset       int    `json:"offset"`
}

type AdminUserSummary struct {
	ID                    string     `json:"id"`
	Email                 string     `json:"email"`
	DisplayName           string     `json:"display_name"`
	PlatformRole          string     `json:"platform_role"`
	Status                string     `json:"status"`
	EmailVerifiedAt       *time.Time `json:"email_verified_at"`
	MFAEnabledAt          *time.Time `json:"mfa_enabled_at"`
	FailedLoginCount      int        `json:"failed_login_count"`
	LockedUntil           *time.Time `json:"locked_until"`
	LastLoginAt           *time.Time `json:"last_login_at"`
	CreatedAt             time.Time  `json:"created_at"`
	ProjectCount          int        `json:"project_count"`
	ScanCount             int        `json:"scan_count"`
}

type PlatformStats struct {
	TotalUsers        int64   `json:"total_users"`
	ActiveUsers       int64   `json:"active_users"`
	TotalProjects     int64   `json:"total_projects"`
	TotalScans        int64   `json:"total_scans"`
	CompletedScans    int64   `json:"completed_scans"`
	AverageScore      float64 `json:"average_score"`
	TotalFindings     int64   `json:"total_findings"`
	TotalStorageBytes int64   `json:"total_storage_bytes"`
	TotalAgentRuns    int64   `json:"total_agent_runs"`
}

type AuditEventRow struct {
	ID           int64           `json:"id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	ActorUserID  *string         `json:"actor_user_id"`
	ActorType    string          `json:"actor_type"`
	Action       string          `json:"action"`
	TargetType   *string         `json:"target_type"`
	TargetID     *string         `json:"target_id"`
	Outcome      string          `json:"outcome"`
	IPAddress    *string         `json:"ip_address"`
	Metadata     json.RawMessage `json:"metadata"`
	PrevHashHex  string          `json:"prev_hash_hex"`
	RowHashHex   string          `json:"row_hash_hex"`
}

// ListAdminUsers queries users with associated activity metrics.
func (s *Store) ListAdminUsers(ctx context.Context, f AdminUserFilter) ([]AdminUserSummary, int, error) {
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 25
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	whereClause := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if f.Search != "" {
		whereClause += fmt.Sprintf(" AND (u.email ILIKE $%d OR u.display_name ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+f.Search+"%")
		argIdx++
	}
	if f.Status != "" && f.Status != "all" {
		whereClause += fmt.Sprintf(" AND u.status = $%d", argIdx)
		args = append(args, f.Status)
		argIdx++
	}
	if f.PlatformRole != "" && f.PlatformRole != "all" {
		whereClause += fmt.Sprintf(" AND u.platform_role = $%d", argIdx)
		args = append(args, f.PlatformRole)
		argIdx++
	}

	var totalCount int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users u %s;", whereClause)
	if err := s.Pool.QueryRow(ctx, countQuery, args...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	selectQuery := fmt.Sprintf(`
		SELECT u.id, u.email, u.display_name, u.platform_role, u.status,
		       u.email_verified_at, u.mfa_enabled_at, u.failed_login_count,
		       u.locked_until, u.last_login_at, u.created_at,
		       (SELECT COUNT(*) FROM projects p JOIN organization_members m ON m.organization_id = p.organization_id WHERE m.user_id = u.id) as project_count,
		       (SELECT COUNT(*) FROM scans sc JOIN projects p ON p.id = sc.project_id JOIN organization_members m ON m.organization_id = p.organization_id WHERE m.user_id = u.id) as scan_count
		FROM users u
		%s
		ORDER BY u.created_at DESC
		LIMIT $%d OFFSET $%d;
	`, whereClause, argIdx, argIdx+1)

	args = append(args, f.Limit, f.Offset)
	rows, err := s.Pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list users query: %w", err)
	}
	defer rows.Close()

	var list []AdminUserSummary
	for rows.Next() {
		var u AdminUserSummary
		if err := rows.Scan(
			&u.ID, &u.Email, &u.DisplayName, &u.PlatformRole, &u.Status,
			&u.EmailVerifiedAt, &u.MFAEnabledAt, &u.FailedLoginCount,
			&u.LockedUntil, &u.LastLoginAt, &u.CreatedAt,
			&u.ProjectCount, &u.ScanCount,
		); err != nil {
			return nil, 0, fmt.Errorf("scan admin user: %w", err)
		}
		list = append(list, u)
	}

	return list, totalCount, nil
}

// UpdateUserStatusByAdmin changes user account status or clears lockouts.
func (s *Store) UpdateUserStatusByAdmin(ctx context.Context, targetUserID, status string, lockedUntil *time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE users
		SET status = $1,
		    locked_until = $2,
		    failed_login_count = CASE WHEN $1 = 'active' THEN 0 ELSE failed_login_count END,
		    updated_at = now()
		WHERE id = $3;
	`, status, lockedUntil, targetUserID)
	return err
}

// GetPlatformStats computes aggregated platform metrics.
func (s *Store) GetPlatformStats(ctx context.Context) (*PlatformStats, error) {
	var st PlatformStats

	_ = s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users;`).Scan(&st.TotalUsers)
	_ = s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE status = 'active';`).Scan(&st.ActiveUsers)
	_ = s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM projects;`).Scan(&st.TotalProjects)
	_ = s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scans;`).Scan(&st.TotalScans)
	_ = s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scans WHERE status = 'completed';`).Scan(&st.CompletedScans)
	_ = s.Pool.QueryRow(ctx, `SELECT COALESCE(AVG(security_score), 100.0) FROM scans WHERE status = 'completed' AND security_score IS NOT NULL;`).Scan(&st.AverageScore)
	_ = s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM findings;`).Scan(&st.TotalFindings)
	_ = s.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(size_bytes), 0) FROM artifacts;`).Scan(&st.TotalStorageBytes)
	_ = s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_runs;`).Scan(&st.TotalAgentRuns)

	return &st, nil
}

// ListAuditEvents queries recent audit log events for administrator inspection.
func (s *Store) ListAuditEvents(ctx context.Context, limit, offset int, actionFilter *string) ([]AuditEventRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, occurred_at, actor_user_id, actor_type, action,
		       target_type, target_id, outcome, ip_address, metadata,
		       prev_hash, row_hash
		FROM audit_events
	`
	args := []any{}
	if actionFilter != nil && *actionFilter != "" {
		query += " WHERE action ILIKE $1 ORDER BY id DESC LIMIT $2 OFFSET $3;"
		args = append(args, "%"+*actionFilter+"%", limit, offset)
	} else {
		query += " ORDER BY id DESC LIMIT $1 OFFSET $2;"
		args = append(args, limit, offset)
	}

	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var events []AuditEventRow
	for rows.Next() {
		var e AuditEventRow
		var ip *net.IPNet
		var metaBytes, prevBytes, rowBytes []byte
		if err := rows.Scan(
			&e.ID, &e.OccurredAt, &e.ActorUserID, &e.ActorType, &e.Action,
			&e.TargetType, &e.TargetID, &e.Outcome, &ip, &metaBytes,
			&prevBytes, &rowBytes,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if ip != nil {
			ipStr := ip.IP.String()
			e.IPAddress = &ipStr
		}
		e.Metadata = json.RawMessage(metaBytes)
		e.PrevHashHex = hex.EncodeToString(prevBytes)
		e.RowHashHex = hex.EncodeToString(rowBytes)
		events = append(events, e)
	}

	return events, nil
}
