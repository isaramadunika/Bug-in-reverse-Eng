package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrUnauthorizedScan = errors.New("cannot start scan without a valid, active Attestation of Authorization")
	ErrProjectNotFound  = errors.New("project not found")
	ErrArtifactNotFound = errors.New("artifact not found")
	ErrScanNotFound     = errors.New("scan not found")
	ErrInvalidProfile   = errors.New("invalid scan profile specified")
)

type Project struct {
	ID               string    `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	PackageName      *string   `json:"package_name"`
	ApplicationOwner string    `json:"application_owner"`
	Environment      string    `json:"environment"`
	Tags             []string  `json:"tags"`
	CreatedBy        *string   `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type ProjectSummary struct {
	Project
	ScanCount          int        `json:"scan_count"`
	LatestScore        *int       `json:"latest_score"`
	LatestScanStatus   *string    `json:"latest_scan_status"`
	LatestScanAt       *time.Time `json:"latest_scan_at"`
	HasActiveAuth      bool       `json:"has_active_auth"`
	ActiveAuthRecordID *string    `json:"active_auth_record_id"`
}

type ProjectDetail struct {
	ProjectSummary
	ActiveAuthorization *AuthorizationRecord `json:"active_authorization,omitempty"`
}

type CreateProjectInput struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	PackageName      *string  `json:"package_name"`
	ApplicationOwner string   `json:"application_owner"`
	Environment      string   `json:"environment"`
	Tags             []string `json:"tags"`
}

type UpdateProjectInput struct {
	Name             *string   `json:"name"`
	Description      *string   `json:"description"`
	PackageName      *string   `json:"package_name"`
	ApplicationOwner *string   `json:"application_owner"`
	Environment      *string   `json:"environment"`
	Tags             *[]string `json:"tags"`
}

type AuthorizationRecord struct {
	ID                      string     `json:"id"`
	ProjectID               string     `json:"project_id"`
	AttestedBy              string     `json:"attested_by"`
	AttestorName            string     `json:"attestor_name,omitempty"`
	Basis                   string     `json:"basis"`
	ScopeDescription        string     `json:"scope_description"`
	AllowsDynamicValidation bool       `json:"allows_dynamic_validation"`
	ReferenceURL            *string    `json:"reference_url"`
	ValidFrom               time.Time  `json:"valid_from"`
	ValidUntil              *time.Time `json:"valid_until"`
	IPAddress               *string    `json:"ip_address"`
	CreatedAt               time.Time  `json:"created_at"`
	RevokedAt               *time.Time `json:"revoked_at"`
}

type CreateAuthRecordInput struct {
	Basis                   string     `json:"basis"`
	ScopeDescription        string     `json:"scope_description"`
	AllowsDynamicValidation bool       `json:"allows_dynamic_validation"`
	ReferenceURL            *string    `json:"reference_url"`
	ValidUntil              *time.Time `json:"valid_until"`
}

type Artifact struct {
	ID               string    `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	SHA256           string    `json:"sha256"`
	SizeBytes        int64     `json:"size_bytes"`
	StorageKey       string    `json:"storage_key"`
	ValidationStatus string    `json:"validation_status"`
	ValidationError  *string   `json:"validation_error"`
	CreatedAt        time.Time `json:"created_at"`
}

type ArtifactVersion struct {
	ID               string    `json:"id"`
	ProjectID        string    `json:"project_id"`
	ArtifactID       string    `json:"artifact_id"`
	OriginalFilename string    `json:"original_filename"`
	Source           string    `json:"source"`
	SourceURL        *string   `json:"source_url"`
	PackageName      *string   `json:"package_name"`
	VersionName      *string   `json:"version_name"`
	VersionCode      *int64    `json:"version_code"`
	MinSDK           *int      `json:"min_sdk"`
	TargetSDK        *int      `json:"target_sdk"`
	Permissions      []string  `json:"permissions"`
	UploadedBy       *string   `json:"uploaded_by"`
	CreatedAt        time.Time `json:"created_at"`
}

type ArtifactVersionDetail struct {
	ArtifactVersion
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	StorageKey string `json:"storage_key"`
}

type CreateArtifactVersionInput struct {
	OriginalFilename string
	Source           string
	SourceURL        *string
	PackageName      *string
	VersionName      *string
	VersionCode      *int64
	MinSDK           *int
	TargetSDK        *int
	Permissions      []string
	UploadedBy       string
}

type Scan struct {
	ID                    string     `json:"id"`
	ProjectID             string     `json:"project_id"`
	ArtifactVersionID     string     `json:"artifact_version_id"`
	ProfileID             string     `json:"profile_id"`
	AuthorizationRecordID string     `json:"authorization_record_id"`
	Status                string     `json:"status"`
	CurrentStage          *string    `json:"current_stage"`
	LastCompletedStage    *string    `json:"last_completed_stage"`
	ProgressNumerator     *int       `json:"progress_numerator"`
	ProgressDenominator   *int       `json:"progress_denominator"`
	FailureReason         *string    `json:"failure_reason"`
	SecurityScore         *int       `json:"security_score"`
	ScoreState            *string    `json:"score_state"`
	ScoreVersion          *string    `json:"score_version"`
	ScoreBreakdown        any        `json:"score_breakdown"`
	AnalysisCoverage      any        `json:"analysis_coverage"`
	RequestedBy           *string    `json:"requested_by"`
	CreatedAt             time.Time  `json:"created_at"`
	StartedAt             *time.Time `json:"started_at"`
	FinishedAt            *time.Time `json:"finished_at"`
}

type ScanSummary struct {
	Scan
	OriginalFilename string  `json:"original_filename"`
	PackageName      *string `json:"package_name"`
	VersionName      *string `json:"version_name"`
	FindingsCount    int     `json:"findings_count"`
}

type ScanStageEvent struct {
	ID         int64     `json:"id"`
	ScanID     string    `json:"scan_id"`
	Stage      string    `json:"stage"`
	Status     string    `json:"status"`
	Message    *string   `json:"message"`
	DurationMS *int      `json:"duration_ms"`
	CreatedAt  time.Time `json:"created_at"`
}

type ScanDetail struct {
	ScanSummary
	Stages []ScanStageEvent `json:"stages"`
}

// UserPersonalOrgID returns the personal organization for a user.
func (s *Store) UserPersonalOrgID(ctx context.Context, userID string) (string, error) {
	var orgID string
	err := s.Pool.QueryRow(ctx, `
		SELECT o.id
		FROM organizations o
		JOIN organization_members om ON om.organization_id = o.id
		WHERE om.user_id = $1 AND o.is_personal = true
		LIMIT 1
	`, userID).Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Fallback to any organization the user belongs to
		err = s.Pool.QueryRow(ctx, `
			SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1
		`, userID).Scan(&orgID)
	}
	return orgID, err
}

// ListProjects returns all non-deleted projects for the organization with summary scan stats.
func (s *Store) ListProjects(ctx context.Context, orgID string) ([]ProjectSummary, error) {
	query := `
		SELECT
			p.id, p.organization_id, p.name, p.description, p.package_name,
			p.application_owner, p.environment, p.tags, p.created_by, p.created_at, p.updated_at,
			COALESCE(sc.scan_count, 0) AS scan_count,
			ls.security_score, ls.status AS latest_scan_status, ls.created_at AS latest_scan_at,
			(ar.id IS NOT NULL) AS has_active_auth,
			ar.id AS active_auth_record_id
		FROM projects p
		LEFT JOIN LATERAL (
			SELECT COUNT(*)::int AS scan_count
			FROM scans s WHERE s.project_id = p.id
		) sc ON true
		LEFT JOIN LATERAL (
			SELECT s.security_score, s.status, s.created_at
			FROM scans s
			WHERE s.project_id = p.id
			ORDER BY s.created_at DESC
			LIMIT 1
		) ls ON true
		LEFT JOIN LATERAL (
			SELECT a.id
			FROM authorization_records a
			WHERE a.project_id = p.id
			  AND a.revoked_at IS NULL
			  AND a.valid_from <= now()
			  AND (a.valid_until IS NULL OR a.valid_until > now())
			ORDER BY a.created_at DESC
			LIMIT 1
		) ar ON true
		WHERE p.organization_id = $1 AND p.deleted_at IS NULL
		ORDER BY p.updated_at DESC
	`

	rows, err := s.Pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []ProjectSummary
	for rows.Next() {
		var ps ProjectSummary
		err := rows.Scan(
			&ps.ID, &ps.OrganizationID, &ps.Name, &ps.Description, &ps.PackageName,
			&ps.ApplicationOwner, &ps.Environment, &ps.Tags, &ps.CreatedBy, &ps.CreatedAt, &ps.UpdatedAt,
			&ps.ScanCount,
			&ps.LatestScore, &ps.LatestScanStatus, &ps.LatestScanAt,
			&ps.HasActiveAuth, &ps.ActiveAuthRecordID,
		)
		if err != nil {
			return nil, err
		}
		projects = append(projects, ps)
	}
	return projects, rows.Err()
}

// GetProject returns a single project detail.
func (s *Store) GetProject(ctx context.Context, orgID, projectID string) (*ProjectDetail, error) {
	query := `
		SELECT
			p.id, p.organization_id, p.name, p.description, p.package_name,
			p.application_owner, p.environment, p.tags, p.created_by, p.created_at, p.updated_at,
			COALESCE(sc.scan_count, 0) AS scan_count,
			ls.security_score, ls.status AS latest_scan_status, ls.created_at AS latest_scan_at,
			(ar.id IS NOT NULL) AS has_active_auth,
			ar.id AS active_auth_record_id
		FROM projects p
		LEFT JOIN LATERAL (
			SELECT COUNT(*)::int AS scan_count
			FROM scans s WHERE s.project_id = p.id
		) sc ON true
		LEFT JOIN LATERAL (
			SELECT s.security_score, s.status, s.created_at
			FROM scans s
			WHERE s.project_id = p.id
			ORDER BY s.created_at DESC
			LIMIT 1
		) ls ON true
		LEFT JOIN LATERAL (
			SELECT a.id
			FROM authorization_records a
			WHERE a.project_id = p.id
			  AND a.revoked_at IS NULL
			  AND a.valid_from <= now()
			  AND (a.valid_until IS NULL OR a.valid_until > now())
			ORDER BY a.created_at DESC
			LIMIT 1
		) ar ON true
		WHERE p.organization_id = $1 AND p.id = $2 AND p.deleted_at IS NULL
	`

	var pd ProjectDetail
	err := s.Pool.QueryRow(ctx, query, orgID, projectID).Scan(
		&pd.ID, &pd.OrganizationID, &pd.Name, &pd.Description, &pd.PackageName,
		&pd.ApplicationOwner, &pd.Environment, &pd.Tags, &pd.CreatedBy, &pd.CreatedAt, &pd.UpdatedAt,
		&pd.ScanCount,
		&pd.LatestScore, &pd.LatestScanStatus, &pd.LatestScanAt,
		&pd.HasActiveAuth, &pd.ActiveAuthRecordID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProjectNotFound
	}
	if err != nil {
		return nil, err
	}

	if pd.HasActiveAuth && pd.ActiveAuthRecordID != nil {
		authRec, err := s.GetAuthorizationRecord(ctx, *pd.ActiveAuthRecordID)
		if err == nil {
			pd.ActiveAuthorization = authRec
		}
	}

	return &pd, nil
}

// CreateProject inserts a new project for the organization.
func (s *Store) CreateProject(ctx context.Context, orgID, userID string, p *CreateProjectInput) (*Project, error) {
	tags := p.Tags
	if tags == nil {
		tags = []string{}
	}
	env := p.Environment
	if env == "" {
		env = "production"
	}

	var proj Project
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO projects (
			organization_id, name, description, package_name,
			application_owner, environment, tags, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, organization_id, name, description, package_name,
			application_owner, environment, tags, created_by, created_at, updated_at
	`, orgID, p.Name, p.Description, p.PackageName, p.ApplicationOwner, env, tags, userID).Scan(
		&proj.ID, &proj.OrganizationID, &proj.Name, &proj.Description, &proj.PackageName,
		&proj.ApplicationOwner, &proj.Environment, &proj.Tags, &proj.CreatedBy, &proj.CreatedAt, &proj.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Add user as admin in project_members
	_, _ = s.Pool.Exec(ctx, `
		INSERT INTO project_members (project_id, user_id, role)
		VALUES ($1, $2, 'admin')
		ON CONFLICT (project_id, user_id) DO NOTHING
	`, proj.ID, userID)

	return &proj, nil
}

// UpdateProject updates mutable metadata for a project.
func (s *Store) UpdateProject(ctx context.Context, orgID, projectID string, p *UpdateProjectInput) (*Project, error) {
	var proj Project
	err := s.Pool.QueryRow(ctx, `
		UPDATE projects SET
			name = COALESCE($3, name),
			description = COALESCE($4, description),
			package_name = COALESCE($5, package_name),
			application_owner = COALESCE($6, application_owner),
			environment = COALESCE($7, environment),
			tags = COALESCE($8, tags),
			updated_at = now()
		WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL
		RETURNING id, organization_id, name, description, package_name,
			application_owner, environment, tags, created_by, created_at, updated_at
	`, projectID, orgID, p.Name, p.Description, p.PackageName, p.ApplicationOwner, p.Environment, p.Tags).Scan(
		&proj.ID, &proj.OrganizationID, &proj.Name, &proj.Description, &proj.PackageName,
		&proj.ApplicationOwner, &proj.Environment, &proj.Tags, &proj.CreatedBy, &proj.CreatedAt, &proj.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProjectNotFound
	}
	return &proj, err
}

// DeleteProject soft-deletes a project.
func (s *Store) DeleteProject(ctx context.Context, orgID, projectID string) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE projects SET deleted_at = now(), updated_at = now()
		WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL
	`, projectID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProjectNotFound
	}
	return nil
}

// CreateAuthorizationRecord records a legally binding Attestation of Authorization.
func (s *Store) CreateAuthorizationRecord(ctx context.Context, orgID, projectID, userID string, r *CreateAuthRecordInput, ip string) (*AuthorizationRecord, error) {
	// Verify project exists in org
	var count int
	err := s.Pool.QueryRow(ctx, `SELECT 1 FROM projects WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`, projectID, orgID).Scan(&count)
	if err != nil {
		return nil, ErrProjectNotFound
	}

	var rec AuthorizationRecord
	var ipParam *string
	if ip != "" {
		ipParam = &ip
	}

	err = s.Pool.QueryRow(ctx, `
		INSERT INTO authorization_records (
			project_id, attested_by, basis, scope_description,
			allows_dynamic_validation, reference_url, valid_until, ip_address
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet)
		RETURNING id, project_id, attested_by, basis, scope_description,
			allows_dynamic_validation, reference_url, valid_from, valid_until,
			host(ip_address), created_at, revoked_at
	`, projectID, userID, r.Basis, r.ScopeDescription, r.AllowsDynamicValidation, r.ReferenceURL, r.ValidUntil, ipParam).Scan(
		&rec.ID, &rec.ProjectID, &rec.AttestedBy, &rec.Basis, &rec.ScopeDescription,
		&rec.AllowsDynamicValidation, &rec.ReferenceURL, &rec.ValidFrom, &rec.ValidUntil,
		&rec.IPAddress, &rec.CreatedAt, &rec.RevokedAt,
	)
	return &rec, err
}

// GetAuthorizationRecord retrieves an authorization record with the attestor's name.
func (s *Store) GetAuthorizationRecord(ctx context.Context, authID string) (*AuthorizationRecord, error) {
	var rec AuthorizationRecord
	err := s.Pool.QueryRow(ctx, `
		SELECT
			ar.id, ar.project_id, ar.attested_by, ar.basis, ar.scope_description,
			ar.allows_dynamic_validation, ar.reference_url, ar.valid_from, ar.valid_until,
			host(ar.ip_address), ar.created_at, ar.revoked_at,
			COALESCE(u.display_name, u.email, 'Unknown') AS attestor_name
		FROM authorization_records ar
		LEFT JOIN users u ON u.id = ar.attested_by
		WHERE ar.id = $1
	`, authID).Scan(
		&rec.ID, &rec.ProjectID, &rec.AttestedBy, &rec.Basis, &rec.ScopeDescription,
		&rec.AllowsDynamicValidation, &rec.ReferenceURL, &rec.ValidFrom, &rec.ValidUntil,
		&rec.IPAddress, &rec.CreatedAt, &rec.RevokedAt, &rec.AttestorName,
	)
	return &rec, err
}

// ListAuthorizationRecords lists all authorization records for a project.
func (s *Store) ListAuthorizationRecords(ctx context.Context, orgID, projectID string) ([]AuthorizationRecord, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT
			ar.id, ar.project_id, ar.attested_by, ar.basis, ar.scope_description,
			ar.allows_dynamic_validation, ar.reference_url, ar.valid_from, ar.valid_until,
			host(ar.ip_address), ar.created_at, ar.revoked_at,
			COALESCE(u.display_name, u.email, 'Unknown') AS attestor_name
		FROM authorization_records ar
		JOIN projects p ON p.id = ar.project_id
		LEFT JOIN users u ON u.id = ar.attested_by
		WHERE p.organization_id = $1 AND p.id = $2 AND p.deleted_at IS NULL
		ORDER BY ar.created_at DESC
	`, orgID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []AuthorizationRecord
	for rows.Next() {
		var rec AuthorizationRecord
		err := rows.Scan(
			&rec.ID, &rec.ProjectID, &rec.AttestedBy, &rec.Basis, &rec.ScopeDescription,
			&rec.AllowsDynamicValidation, &rec.ReferenceURL, &rec.ValidFrom, &rec.ValidUntil,
			&rec.IPAddress, &rec.CreatedAt, &rec.RevokedAt, &rec.AttestorName,
		)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// HasActiveAuthorization checks whether the project has a valid, unrevoked authorization record.
func (s *Store) HasActiveAuthorization(ctx context.Context, projectID string) (bool, string, error) {
	var authID string
	err := s.Pool.QueryRow(ctx, `
		SELECT id
		FROM authorization_records
		WHERE project_id = $1
		  AND revoked_at IS NULL
		  AND valid_from <= now()
		  AND (valid_until IS NULL OR valid_until > now())
		ORDER BY created_at DESC
		LIMIT 1
	`, projectID).Scan(&authID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, authID, nil
}

// CreateOrGetArtifact ensures content-addressed dedup of an APK artifact per organization.
func (s *Store) CreateOrGetArtifact(ctx context.Context, orgID, sha256Hex string, sizeBytes int64, storageKey string) (*Artifact, error) {
	var art Artifact
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO artifacts (organization_id, sha256, size_bytes, storage_key, validation_status)
		VALUES ($1, $2, $3, $4, 'valid')
		ON CONFLICT (organization_id, sha256) DO UPDATE
		SET size_bytes = EXCLUDED.size_bytes
		RETURNING id, organization_id, sha256, size_bytes, storage_key, validation_status, validation_error, created_at
	`, orgID, sha256Hex, sizeBytes, storageKey).Scan(
		&art.ID, &art.OrganizationID, &art.SHA256, &art.SizeBytes, &art.StorageKey,
		&art.ValidationStatus, &art.ValidationError, &art.CreatedAt,
	)
	return &art, err
}

// CreateArtifactVersion creates an artifact version record associated with a project.
func (s *Store) CreateArtifactVersion(ctx context.Context, projectID, artifactID string, input *CreateArtifactVersionInput) (*ArtifactVersion, error) {
	permissions := input.Permissions
	if permissions == nil {
		permissions = []string{}
	}

	var av ArtifactVersion
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO artifact_versions (
			project_id, artifact_id, original_filename, source, source_url,
			package_name, version_name, version_code, min_sdk, target_sdk,
			permissions, uploaded_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, project_id, artifact_id, original_filename, source, source_url,
			package_name, version_name, version_code, min_sdk, target_sdk,
			permissions, uploaded_by, created_at
	`, projectID, artifactID, input.OriginalFilename, input.Source, input.SourceURL,
		input.PackageName, input.VersionName, input.VersionCode, input.MinSDK, input.TargetSDK,
		permissions, input.UploadedBy).Scan(
		&av.ID, &av.ProjectID, &av.ArtifactID, &av.OriginalFilename, &av.Source, &av.SourceURL,
		&av.PackageName, &av.VersionName, &av.VersionCode, &av.MinSDK, &av.TargetSDK,
		&av.Permissions, &av.UploadedBy, &av.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Update project package_name if it is currently NULL and we discovered one
	if input.PackageName != nil && *input.PackageName != "" {
		_, _ = s.Pool.Exec(ctx, `
			UPDATE projects SET package_name = $2, updated_at = now()
			WHERE id = $1 AND (package_name IS NULL OR package_name = '')
		`, projectID, *input.PackageName)
	}

	return &av, nil
}

// ListArtifactVersions lists versions for a project.
func (s *Store) ListArtifactVersions(ctx context.Context, orgID, projectID string) ([]ArtifactVersion, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT
			av.id, av.project_id, av.artifact_id, av.original_filename, av.source, av.source_url,
			av.package_name, av.version_name, av.version_code, av.min_sdk, av.target_sdk,
			av.permissions, av.uploaded_by, av.created_at
		FROM artifact_versions av
		JOIN projects p ON p.id = av.project_id
		WHERE p.organization_id = $1 AND p.id = $2 AND p.deleted_at IS NULL
		ORDER BY av.created_at DESC
	`, orgID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []ArtifactVersion
	for rows.Next() {
		var av ArtifactVersion
		err := rows.Scan(
			&av.ID, &av.ProjectID, &av.ArtifactID, &av.OriginalFilename, &av.Source, &av.SourceURL,
			&av.PackageName, &av.VersionName, &av.VersionCode, &av.MinSDK, &av.TargetSDK,
			&av.Permissions, &av.UploadedBy, &av.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		versions = append(versions, av)
	}
	return versions, rows.Err()
}

// GetArtifactVersion retrieves a version with underlying artifact storage details.
func (s *Store) GetArtifactVersion(ctx context.Context, orgID, versionID string) (*ArtifactVersionDetail, error) {
	var avd ArtifactVersionDetail
	err := s.Pool.QueryRow(ctx, `
		SELECT
			av.id, av.project_id, av.artifact_id, av.original_filename, av.source, av.source_url,
			av.package_name, av.version_name, av.version_code, av.min_sdk, av.target_sdk,
			av.permissions, av.uploaded_by, av.created_at,
			a.sha256, a.size_bytes, a.storage_key
		FROM artifact_versions av
		JOIN artifacts a ON a.id = av.artifact_id
		JOIN projects p ON p.id = av.project_id
		WHERE p.organization_id = $1 AND av.id = $2 AND p.deleted_at IS NULL
	`, orgID, versionID).Scan(
		&avd.ID, &avd.ProjectID, &avd.ArtifactID, &avd.OriginalFilename, &avd.Source, &avd.SourceURL,
		&avd.PackageName, &avd.VersionName, &avd.VersionCode, &avd.MinSDK, &avd.TargetSDK,
		&avd.Permissions, &avd.UploadedBy, &avd.CreatedAt,
		&avd.SHA256, &avd.SizeBytes, &avd.StorageKey,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrArtifactNotFound
	}
	return &avd, err
}

// CreateScan enqueues a new scan and creates the initial scan_job in a single transaction.
func (s *Store) CreateScan(ctx context.Context, orgID, projectID, artifactVersionID, profileID, authRecordID, requestedBy, idempotencyKey string) (*Scan, error) {
	var scan Scan

	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// 1. Verify project exists in organization
		var exists bool
		err := tx.QueryRow(ctx, `SELECT true FROM projects WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`, projectID, orgID).Scan(&exists)
		if err != nil || !exists {
			return ErrProjectNotFound
		}

		// 2. Verify authorization record is valid and active
		var authValid bool
		err = tx.QueryRow(ctx, `
			SELECT true FROM authorization_records
			WHERE id = $1 AND project_id = $2 AND revoked_at IS NULL
			  AND valid_from <= now() AND (valid_until IS NULL OR valid_until > now())
		`, authRecordID, projectID).Scan(&authValid)
		if err != nil || !authValid {
			return ErrUnauthorizedScan
		}

		// 3. Verify scan profile
		var profileExists bool
		err = tx.QueryRow(ctx, `SELECT true FROM scan_profiles WHERE id = $1`, profileID).Scan(&profileExists)
		if err != nil || !profileExists {
			return ErrInvalidProfile
		}

		// 4. Insert scan
		var ik *string
		if idempotencyKey != "" {
			ik = &idempotencyKey
		}

		err = tx.QueryRow(ctx, `
			INSERT INTO scans (
				project_id, artifact_version_id, profile_id, authorization_record_id,
				status, requested_by, idempotency_key
			) VALUES ($1, $2, $3, $4, 'queued', $5, $6)
			RETURNING id, project_id, artifact_version_id, profile_id, authorization_record_id,
				status, current_stage, last_completed_stage, progress_numerator, progress_denominator,
				failure_reason, security_score, score_state, score_version, score_breakdown,
				analysis_coverage, requested_by, created_at, started_at, finished_at
		`, projectID, artifactVersionID, profileID, authRecordID, requestedBy, ik).Scan(
			&scan.ID, &scan.ProjectID, &scan.ArtifactVersionID, &scan.ProfileID, &scan.AuthorizationRecordID,
			&scan.Status, &scan.CurrentStage, &scan.LastCompletedStage, &scan.ProgressNumerator, &scan.ProgressDenominator,
			&scan.FailureReason, &scan.SecurityScore, &scan.ScoreState, &scan.ScoreVersion, &scan.ScoreBreakdown,
			&scan.AnalysisCoverage, &scan.RequestedBy, &scan.CreatedAt, &scan.StartedAt, &scan.FinishedAt,
		)
		if err != nil {
			return fmt.Errorf("insert scan: %w", err)
		}

		// 5. Insert scan_jobs row for static analysis worker
		_, err = tx.Exec(ctx, `
			INSERT INTO scan_jobs (scan_id, kind, status, priority, payload)
			VALUES ($1::uuid, 'static_analysis', 'queued', 100, jsonb_build_object(
				'scan_id', $1::text,
				'profile_id', $2::text,
				'artifact_version_id', $3::text
			))
		`, scan.ID, profileID, artifactVersionID)
		if err != nil {
			return fmt.Errorf("insert scan_job: %w", err)
		}

		// 6. Record initial scan stage event
		_, err = tx.Exec(ctx, `
			INSERT INTO scan_stage_events (scan_id, stage, status, message)
			VALUES ($1, 'queued', 'started', 'Scan queued for static analysis worker')
		`, scan.ID)
		return err
	})

	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// GetScan retrieves a scan with stage events and artifact summary.
func (s *Store) GetScan(ctx context.Context, orgID, scanID string) (*ScanDetail, error) {
	var sd ScanDetail
	err := s.Pool.QueryRow(ctx, `
		SELECT
			s.id, s.project_id, s.artifact_version_id, s.profile_id, s.authorization_record_id,
			s.status, s.current_stage, s.last_completed_stage, s.progress_numerator, s.progress_denominator,
			s.failure_reason, s.security_score, s.score_state, s.score_version, s.score_breakdown,
			s.analysis_coverage, s.requested_by, s.created_at, s.started_at, s.finished_at,
			av.original_filename, av.package_name, av.version_name,
			(SELECT COUNT(*)::int FROM findings f WHERE f.scan_id = s.id) AS findings_count
		FROM scans s
		JOIN projects p ON p.id = s.project_id
		JOIN artifact_versions av ON av.id = s.artifact_version_id
		WHERE p.organization_id = $1 AND s.id = $2 AND p.deleted_at IS NULL
	`, orgID, scanID).Scan(
		&sd.ID, &sd.ProjectID, &sd.ArtifactVersionID, &sd.ProfileID, &sd.AuthorizationRecordID,
		&sd.Status, &sd.CurrentStage, &sd.LastCompletedStage, &sd.ProgressNumerator, &sd.ProgressDenominator,
		&sd.FailureReason, &sd.SecurityScore, &sd.ScoreState, &sd.ScoreVersion, &sd.ScoreBreakdown,
		&sd.AnalysisCoverage, &sd.RequestedBy, &sd.CreatedAt, &sd.StartedAt, &sd.FinishedAt,
		&sd.OriginalFilename, &sd.PackageName, &sd.VersionName, &sd.FindingsCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrScanNotFound
	}
	if err != nil {
		return nil, err
	}

	// Fetch stage events
	rows, err := s.Pool.Query(ctx, `
		SELECT id, scan_id, stage, status, message, duration_ms, created_at
		FROM scan_stage_events
		WHERE scan_id = $1
		ORDER BY id ASC
	`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var se ScanStageEvent
			if err := rows.Scan(&se.ID, &se.ScanID, &se.Stage, &se.Status, &se.Message, &se.DurationMS, &se.CreatedAt); err == nil {
				sd.Stages = append(sd.Stages, se)
			}
		}
	}

	return &sd, nil
}

// ListScans returns all scans for a project.
func (s *Store) ListScans(ctx context.Context, orgID, projectID string) ([]ScanSummary, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT
			s.id, s.project_id, s.artifact_version_id, s.profile_id, s.authorization_record_id,
			s.status, s.current_stage, s.last_completed_stage, s.progress_numerator, s.progress_denominator,
			s.failure_reason, s.security_score, s.score_state, s.score_version, s.score_breakdown,
			s.analysis_coverage, s.requested_by, s.created_at, s.started_at, s.finished_at,
			av.original_filename, av.package_name, av.version_name,
			(SELECT COUNT(*)::int FROM findings f WHERE f.scan_id = s.id) AS findings_count
		FROM scans s
		JOIN projects p ON p.id = s.project_id
		JOIN artifact_versions av ON av.id = s.artifact_version_id
		WHERE p.organization_id = $1 AND p.id = $2 AND p.deleted_at IS NULL
		ORDER BY s.created_at DESC
	`, orgID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanSummary
	for rows.Next() {
		var ss ScanSummary
		err := rows.Scan(
			&ss.ID, &ss.ProjectID, &ss.ArtifactVersionID, &ss.ProfileID, &ss.AuthorizationRecordID,
			&ss.Status, &ss.CurrentStage, &ss.LastCompletedStage, &ss.ProgressNumerator, &ss.ProgressDenominator,
			&ss.FailureReason, &ss.SecurityScore, &ss.ScoreState, &ss.ScoreVersion, &ss.ScoreBreakdown,
			&ss.AnalysisCoverage, &ss.RequestedBy, &ss.CreatedAt, &ss.StartedAt, &ss.FinishedAt,
			&ss.OriginalFilename, &ss.PackageName, &ss.VersionName, &ss.FindingsCount,
		)
		if err != nil {
			return nil, err
		}
		scans = append(scans, ss)
	}
	return scans, rows.Err()
}

// CancelScan marks an active or queued scan as cancelling.
func (s *Store) CancelScan(ctx context.Context, orgID, scanID string) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE scans SET
			status = 'cancelling',
			failure_reason = 'Cancelled by user request'
		WHERE id = $1 AND status IN ('queued', 'running')
		  AND project_id IN (SELECT id FROM projects WHERE organization_id = $2 AND deleted_at IS NULL)
	`, scanID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("scan cannot be cancelled (may be already completed, failed, or not found)")
	}

	// Update any associated queued scan_jobs
	_, _ = s.Pool.Exec(ctx, `
		UPDATE scan_jobs SET status = 'cancelled' WHERE scan_id = $1 AND status = 'queued'
	`, scanID)

	return nil
}
