package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrFindingNotFound = errors.New("finding not found")
	ErrReportNotFound  = errors.New("report not found")
)

type Finding struct {
	ID                    string              `json:"id"`
	ScanID                string              `json:"scan_id"`
	Fingerprint           string              `json:"fingerprint"`
	RuleID                string              `json:"rule_id"`
	RuleVersion           string              `json:"rule_version"`
	Title                 string              `json:"title"`
	Description           string              `json:"description"`
	Severity              string              `json:"severity"`
	Confidence            string              `json:"confidence"`
	VerificationStatus    string              `json:"verification_status"`
	Reachability          string              `json:"reachability"`
	Category              string              `json:"category"`
	CWEIDs                []string            `json:"cwe_ids"`
	MASVSIDs              []string            `json:"masvs_ids"`
	Impact                string              `json:"impact"`
	Preconditions         string              `json:"preconditions"`
	Remediation           string              `json:"remediation"`
	FalsePositiveNotes    string              `json:"false_positive_notes"`
	ReviewStatus          string              `json:"review_status"`
	IncludeInReport       bool                `json:"include_in_report"`
	ReportExclusionReason *string             `json:"report_exclusion_reason"`
	DuplicateOf           *string             `json:"duplicate_of"`
	CreatedAt             time.Time           `json:"created_at"`
	Occurrences           []FindingOccurrence `json:"occurrences,omitempty"`
	Evidence              []EvidenceItem      `json:"evidence,omitempty"`
}

type FindingOccurrence struct {
	ID            string    `json:"id"`
	FindingID     string    `json:"finding_id"`
	FilePath      *string   `json:"file_path"`
	LineStart     *int      `json:"line_start"`
	LineEnd       *int      `json:"line_end"`
	ClassName     *string   `json:"class_name"`
	MethodName    *string   `json:"method_name"`
	ComponentName *string   `json:"component_name"`
	CreatedAt     time.Time `json:"created_at"`
}

type EvidenceItem struct {
	ID                 string          `json:"id"`
	ScanID             string          `json:"scan_id"`
	FindingID          *string         `json:"finding_id"`
	ArtifactSHA256     string          `json:"artifact_sha256"`
	EvidenceType       string          `json:"evidence_type"`
	Location           *string         `json:"location"`
	LineStart          *int            `json:"line_start"`
	LineEnd            *int            `json:"line_end"`
	ByteOffset         *int64          `json:"byte_offset"`
	Excerpt            string          `json:"excerpt"`
	RuleID             *string         `json:"rule_id"`
	AnalysisSource     string          `json:"analysis_source"`
	ToolName           string          `json:"tool_name"`
	ToolVersion        string          `json:"tool_version"`
	Confidence         string          `json:"confidence"`
	VerificationStatus string          `json:"verification_status"`
	Redaction          json.RawMessage `json:"redaction"`
	Provenance         json.RawMessage `json:"provenance"`
	CollectedAt        time.Time       `json:"collected_at"`
}

type FindingFilter struct {
	Severity     *string `json:"severity"`
	ReviewStatus *string `json:"review_status"`
	Category     *string `json:"category"`
	Reachability *string `json:"reachability"`
	Search       *string `json:"search"`
}

type UpdateFindingReviewInput struct {
	ReviewStatus          string  `json:"review_status"`
	IncludeInReport       *bool   `json:"include_in_report"`
	ReportExclusionReason *string `json:"report_exclusion_reason"`
	FalsePositiveNotes    *string `json:"false_positive_notes"`
}

type EvidenceNode struct {
	ID         string          `json:"id"`
	ScanID     string          `json:"scan_id"`
	NodeKey    string          `json:"node_key"`
	NodeType   string          `json:"node_type"`
	Label      string          `json:"label"`
	Severity   *string         `json:"severity"`
	Properties json.RawMessage `json:"properties"`
	EvidenceID *string         `json:"evidence_id"`
}

type EvidenceEdge struct {
	ID             string          `json:"id"`
	ScanID         string          `json:"scan_id"`
	SourceID       string          `json:"source_id"`
	TargetID       string          `json:"target_id"`
	EdgeType       string          `json:"edge_type"`
	RelationStatus string          `json:"relation_status"`
	EvidenceID     *string         `json:"evidence_id"`
	Provenance     json.RawMessage `json:"provenance"`
}

type EvidenceGraph struct {
	Nodes []EvidenceNode `json:"nodes"`
	Edges []EvidenceEdge `json:"edges"`
}

type Report struct {
	ID          string     `json:"id"`
	ScanID      string     `json:"scan_id"`
	Format      string     `json:"format"`
	Status      string     `json:"status"`
	StorageKey  *string    `json:"storage_key"`
	SHA256      *string    `json:"sha256"`
	SizeBytes   *int64     `json:"size_bytes"`
	IsSample    bool       `json:"is_sample"`
	RequestedBy *string    `json:"requested_by"`
	Error       *string    `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	ReadyAt     *time.Time `json:"ready_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// VerifyScanAccess ensures a scan exists and belongs to the given organization.
func (s *Store) VerifyScanAccess(ctx context.Context, orgID, scanID string) error {
	var dummy int
	err := s.Pool.QueryRow(ctx, `
		SELECT 1
		FROM scans s
		JOIN projects p ON p.id = s.project_id
		WHERE s.id = $1 AND p.organization_id = $2;
	`, scanID, orgID).Scan(&dummy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrScanNotFound
		}
		return fmt.Errorf("verify scan access: %w", err)
	}
	return nil
}

// ListFindings retrieves findings for a scan with optional filters, ensuring tenant isolation.
func (s *Store) ListFindings(ctx context.Context, orgID, scanID string, f FindingFilter) ([]Finding, error) {
	if err := s.VerifyScanAccess(ctx, orgID, scanID); err != nil {
		return nil, err
	}

	query := `
		SELECT f.id, f.scan_id, f.fingerprint, f.rule_id, f.rule_version, f.title, f.description,
		       f.severity, f.confidence, f.verification_status, f.reachability, f.category,
		       f.cwe_ids, f.masvs_ids, f.impact, f.preconditions, f.remediation, f.false_positive_notes,
		       f.review_status, f.include_in_report, f.report_exclusion_reason, f.duplicate_of, f.created_at
		FROM findings f
		WHERE f.scan_id = $1
	`
	args := []any{scanID}
	idx := 2

	if f.Severity != nil && *f.Severity != "" {
		query += fmt.Sprintf(" AND f.severity = $%d", idx)
		args = append(args, *f.Severity)
		idx++
	}
	if f.ReviewStatus != nil && *f.ReviewStatus != "" {
		query += fmt.Sprintf(" AND f.review_status = $%d", idx)
		args = append(args, *f.ReviewStatus)
		idx++
	}
	if f.Category != nil && *f.Category != "" {
		query += fmt.Sprintf(" AND f.category = $%d", idx)
		args = append(args, *f.Category)
		idx++
	}
	if f.Reachability != nil && *f.Reachability != "" {
		query += fmt.Sprintf(" AND f.reachability = $%d", idx)
		args = append(args, *f.Reachability)
		idx++
	}
	if f.Search != nil && *f.Search != "" {
		query += fmt.Sprintf(" AND (f.title ILIKE $%d OR f.description ILIKE $%d OR f.rule_id ILIKE $%d)", idx, idx, idx)
		args = append(args, "%"+*f.Search+"%")
		idx++
	}

	query += `
		ORDER BY
			CASE f.severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END ASC,
			f.created_at ASC;
	`

	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var item Finding
		err := rows.Scan(
			&item.ID, &item.ScanID, &item.Fingerprint, &item.RuleID, &item.RuleVersion,
			&item.Title, &item.Description, &item.Severity, &item.Confidence,
			&item.VerificationStatus, &item.Reachability, &item.Category,
			&item.CWEIDs, &item.MASVSIDs, &item.Impact, &item.Preconditions,
			&item.Remediation, &item.FalsePositiveNotes, &item.ReviewStatus,
			&item.IncludeInReport, &item.ReportExclusionReason, &item.DuplicateOf,
			&item.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		findings = append(findings, item)
	}

	return findings, nil
}

// GetFinding retrieves a single finding by ID with occurrences and linked evidence.
func (s *Store) GetFinding(ctx context.Context, orgID, findingID string) (*Finding, error) {
	var item Finding
	err := s.Pool.QueryRow(ctx, `
		SELECT f.id, f.scan_id, f.fingerprint, f.rule_id, f.rule_version, f.title, f.description,
		       f.severity, f.confidence, f.verification_status, f.reachability, f.category,
		       f.cwe_ids, f.masvs_ids, f.impact, f.preconditions, f.remediation, f.false_positive_notes,
		       f.review_status, f.include_in_report, f.report_exclusion_reason, f.duplicate_of, f.created_at
		FROM findings f
		JOIN scans s ON s.id = f.scan_id
		JOIN projects p ON p.id = s.project_id
		WHERE f.id = $1 AND p.organization_id = $2;
	`, findingID, orgID).Scan(
		&item.ID, &item.ScanID, &item.Fingerprint, &item.RuleID, &item.RuleVersion,
		&item.Title, &item.Description, &item.Severity, &item.Confidence,
		&item.VerificationStatus, &item.Reachability, &item.Category,
		&item.CWEIDs, &item.MASVSIDs, &item.Impact, &item.Preconditions,
		&item.Remediation, &item.FalsePositiveNotes, &item.ReviewStatus,
		&item.IncludeInReport, &item.ReportExclusionReason, &item.DuplicateOf,
		&item.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, fmt.Errorf("get finding: %w", err)
	}

	// Fetch occurrences
	occRows, err := s.Pool.Query(ctx, `
		SELECT id, finding_id, file_path, line_start, line_end, class_name, method_name, component_name, created_at
		FROM finding_occurrences
		WHERE finding_id = $1
		ORDER BY created_at ASC;
	`, item.ID)
	if err != nil {
		return nil, fmt.Errorf("fetch occurrences: %w", err)
	}
	defer occRows.Close()

	for occRows.Next() {
		var occ FindingOccurrence
		if err := occRows.Scan(
			&occ.ID, &occ.FindingID, &occ.FilePath, &occ.LineStart, &occ.LineEnd,
			&occ.ClassName, &occ.MethodName, &occ.ComponentName, &occ.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan occurrence: %w", err)
		}
		item.Occurrences = append(item.Occurrences, occ)
	}

	// Fetch evidence items
	evRows, err := s.Pool.Query(ctx, `
		SELECT id, scan_id, finding_id, artifact_sha256, evidence_type, location,
		       line_start, line_end, byte_offset, excerpt, rule_id, analysis_source,
		       tool_name, tool_version, confidence, verification_status, redaction, provenance, collected_at
		FROM evidence
		WHERE finding_id = $1
		ORDER BY collected_at ASC;
	`, item.ID)
	if err != nil {
		return nil, fmt.Errorf("fetch evidence: %w", err)
	}
	defer evRows.Close()

	for evRows.Next() {
		var ev EvidenceItem
		var redactionBytes, provenanceBytes []byte
		if err := evRows.Scan(
			&ev.ID, &ev.ScanID, &ev.FindingID, &ev.ArtifactSHA256, &ev.EvidenceType,
			&ev.Location, &ev.LineStart, &ev.LineEnd, &ev.ByteOffset, &ev.Excerpt,
			&ev.RuleID, &ev.AnalysisSource, &ev.ToolName, &ev.ToolVersion,
			&ev.Confidence, &ev.VerificationStatus, &redactionBytes, &provenanceBytes,
			&ev.CollectedAt,
		); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		ev.Redaction = json.RawMessage(redactionBytes)
		ev.Provenance = json.RawMessage(provenanceBytes)
		item.Evidence = append(item.Evidence, ev)
	}

	return &item, nil
}

// UpdateFindingReview updates the triage status, exclusion from report, and false positive notes.
func (s *Store) UpdateFindingReview(ctx context.Context, orgID, findingID string, in UpdateFindingReviewInput) (*Finding, error) {
	// Validate review_status value
	validStatuses := map[string]bool{
		"open":           true,
		"confirmed":      true,
		"false_positive": true,
		"accepted_risk":  true,
		"fixed":          true,
	}
	if !validStatuses[in.ReviewStatus] {
		return nil, fmt.Errorf("invalid review status: %s", in.ReviewStatus)
	}

	cmd, err := s.Pool.Exec(ctx, `
		UPDATE findings f
		SET review_status = $1,
		    include_in_report = COALESCE($2, f.include_in_report),
		    report_exclusion_reason = COALESCE($3, f.report_exclusion_reason),
		    false_positive_notes = COALESCE($4, f.false_positive_notes)
		FROM scans s
		JOIN projects p ON p.id = s.project_id
		WHERE f.id = $5 AND f.scan_id = s.id AND p.organization_id = $6;
	`, in.ReviewStatus, in.IncludeInReport, in.ReportExclusionReason, in.FalsePositiveNotes, findingID, orgID)
	if err != nil {
		return nil, fmt.Errorf("update finding review: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return nil, ErrFindingNotFound
	}

	return s.GetFinding(ctx, orgID, findingID)
}

// GetEvidenceGraph returns the complete graph (nodes and edges) for a given scan.
func (s *Store) GetEvidenceGraph(ctx context.Context, orgID, scanID string) (*EvidenceGraph, error) {
	if err := s.VerifyScanAccess(ctx, orgID, scanID); err != nil {
		return nil, err
	}

	// Fetch Nodes
	nodeRows, err := s.Pool.Query(ctx, `
		SELECT id, scan_id, node_key, node_type, label, severity, properties, evidence_id
		FROM evidence_nodes
		WHERE scan_id = $1
		ORDER BY node_type ASC, label ASC;
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("fetch evidence nodes: %w", err)
	}
	defer nodeRows.Close()

	var nodes []EvidenceNode
	for nodeRows.Next() {
		var n EvidenceNode
		var propBytes []byte
		if err := nodeRows.Scan(
			&n.ID, &n.ScanID, &n.NodeKey, &n.NodeType, &n.Label,
			&n.Severity, &propBytes, &n.EvidenceID,
		); err != nil {
			return nil, fmt.Errorf("scan evidence node: %w", err)
		}
		n.Properties = json.RawMessage(propBytes)
		nodes = append(nodes, n)
	}

	// Fetch Edges
	edgeRows, err := s.Pool.Query(ctx, `
		SELECT id, scan_id, source_id, target_id, edge_type, relation_status, evidence_id, provenance
		FROM evidence_edges
		WHERE scan_id = $1
		ORDER BY edge_type ASC;
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("fetch evidence edges: %w", err)
	}
	defer edgeRows.Close()

	var edges []EvidenceEdge
	for edgeRows.Next() {
		var e EvidenceEdge
		var provBytes []byte
		if err := edgeRows.Scan(
			&e.ID, &e.ScanID, &e.SourceID, &e.TargetID, &e.EdgeType,
			&e.RelationStatus, &e.EvidenceID, &provBytes,
		); err != nil {
			return nil, fmt.Errorf("scan evidence edge: %w", err)
		}
		e.Provenance = json.RawMessage(provBytes)
		edges = append(edges, e)
	}

	return &EvidenceGraph{
		Nodes: nodes,
		Edges: edges,
	}, nil
}

// GetScanArtifactStorageKey retrieves the underlying APK storage key and metadata for source inspection.
func (s *Store) GetScanArtifactStorageKey(ctx context.Context, orgID, scanID string) (storageKey string, packageName string, sha256Digest string, err error) {
	var pkg *string
	err = s.Pool.QueryRow(ctx, `
		SELECT a.storage_key, av.package_name, a.sha256
		FROM scans s
		JOIN projects p ON p.id = s.project_id
		JOIN artifact_versions av ON av.id = s.artifact_version_id
		JOIN artifacts a ON a.id = av.artifact_id
		WHERE s.id = $1 AND p.organization_id = $2;
	`, scanID, orgID).Scan(&storageKey, &pkg, &sha256Digest)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", "", ErrScanNotFound
		}
		return "", "", "", fmt.Errorf("get scan artifact storage key: %w", err)
	}
	if pkg != nil {
		packageName = *pkg
	}
	return storageKey, packageName, sha256Digest, nil
}

// CreateReport inserts a new queued or generating report record.
func (s *Store) CreateReport(ctx context.Context, r *Report) error {
	return s.Pool.QueryRow(ctx, `
		INSERT INTO reports (scan_id, format, status, requested_by, is_sample)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at;
	`, r.ScanID, r.Format, r.Status, r.RequestedBy, r.IsSample).Scan(&r.ID, &r.CreatedAt)
}

// UpdateReportStatus finalizes report metadata on success or marks it failed.
func (s *Store) UpdateReportStatus(ctx context.Context, reportID string, status string, storageKey *string, sha256Digest *string, sizeBytes *int64, errStr *string) error {
	var readyAt *time.Time
	if status == "ready" {
		t := time.Now()
		readyAt = &t
	}
	_, err := s.Pool.Exec(ctx, `
		UPDATE reports
		SET status = $1,
		    storage_key = $2,
		    sha256 = $3,
		    size_bytes = $4,
		    error = $5,
		    ready_at = $6
		WHERE id = $7;
	`, status, storageKey, sha256Digest, sizeBytes, errStr, readyAt, reportID)
	return err
}

// GetReport retrieves a report record checking tenant isolation.
func (s *Store) GetReport(ctx context.Context, orgID, reportID string) (*Report, error) {
	var r Report
	err := s.Pool.QueryRow(ctx, `
		SELECT r.id, r.scan_id, r.format, r.status, r.storage_key, r.sha256,
		       r.size_bytes, r.is_sample, r.requested_by, r.error, r.created_at, r.ready_at, r.expires_at
		FROM reports r
		JOIN scans s ON s.id = r.scan_id
		JOIN projects p ON p.id = s.project_id
		WHERE r.id = $1 AND p.organization_id = $2;
	`, reportID, orgID).Scan(
		&r.ID, &r.ScanID, &r.Format, &r.Status, &r.StorageKey, &r.SHA256,
		&r.SizeBytes, &r.IsSample, &r.RequestedBy, &r.Error, &r.CreatedAt, &r.ReadyAt, &r.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrReportNotFound
		}
		return nil, fmt.Errorf("get report: %w", err)
	}
	return &r, nil
}

// ListReports lists all reports for a scan.
func (s *Store) ListReports(ctx context.Context, orgID, scanID string) ([]Report, error) {
	if err := s.VerifyScanAccess(ctx, orgID, scanID); err != nil {
		return nil, err
	}

	rows, err := s.Pool.Query(ctx, `
		SELECT id, scan_id, format, status, storage_key, sha256, size_bytes, is_sample, requested_by, error, created_at, ready_at, expires_at
		FROM reports
		WHERE scan_id = $1
		ORDER BY created_at DESC;
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}
	defer rows.Close()

	var out []Report
	for rows.Next() {
		var r Report
		if err := rows.Scan(
			&r.ID, &r.ScanID, &r.Format, &r.Status, &r.StorageKey, &r.SHA256,
			&r.SizeBytes, &r.IsSample, &r.RequestedBy, &r.Error, &r.CreatedAt, &r.ReadyAt, &r.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("scan report row: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

// ComputeSHA256 returns the hex lowercase SHA-256 string for arbitrary bytes.
func ComputeSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
