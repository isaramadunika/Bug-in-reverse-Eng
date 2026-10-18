package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrAgentRunNotFound   = errors.New("agent run not found")
	ErrAIAnalysisNotFound = errors.New("ai analysis not found")
)

type AgentRun struct {
	ID            string     `json:"id"`
	ScanID        string     `json:"scan_id"`
	FindingID     *string    `json:"finding_id"`
	Agent         string     `json:"agent"`
	Provider      string     `json:"provider"`
	Model         string     `json:"model"`
	IsMock        bool       `json:"is_mock"`
	Status        string     `json:"status"`
	Iterations    int        `json:"iterations"`
	ToolCalls     int        `json:"tool_calls"`
	InputTokens   int        `json:"input_tokens"`
	OutputTokens  int        `json:"output_tokens"`
	CostUSDMicros int64      `json:"cost_usd_micros"`
	Error         *string    `json:"error"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
}

type AIAnalysis struct {
	ID               string          `json:"id"`
	AgentRunID       string          `json:"agent_run_id"`
	ScanID           string          `json:"scan_id"`
	FindingID        *string         `json:"finding_id"`
	Kind             string          `json:"kind"`
	Output           json.RawMessage `json:"output"`
	CitedEvidenceIDs []string        `json:"cited_evidence_ids"`
	SchemaVersion    string          `json:"schema_version"`
	CreatedAt        time.Time       `json:"created_at"`
	CitedEvidence    []EvidenceItem  `json:"cited_evidence,omitempty"`
}

// CreateAgentRun persists a new agent run record in the database.
func (s *Store) CreateAgentRun(ctx context.Context, r *AgentRun) error {
	return s.Pool.QueryRow(ctx, `
		INSERT INTO agent_runs (
			scan_id, finding_id, agent, provider, model, is_mock,
			status, iterations, tool_calls, input_tokens, output_tokens,
			cost_usd_micros, started_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id, started_at;
	`,
		r.ScanID, r.FindingID, r.Agent, r.Provider, r.Model, r.IsMock,
		r.Status, r.Iterations, r.ToolCalls, r.InputTokens, r.OutputTokens,
		r.CostUSDMicros, time.Now(),
	).Scan(&r.ID, &r.StartedAt)
}

// UpdateAgentRun updates execution metrics, status, and finish timestamp.
func (s *Store) UpdateAgentRun(
	ctx context.Context,
	runID string,
	status string,
	iterations int,
	toolCalls int,
	inputTokens int,
	outputTokens int,
	costUSDMicros int64,
	errStr *string,
) error {
	now := time.Now()
	_, err := s.Pool.Exec(ctx, `
		UPDATE agent_runs
		SET status = $1,
		    iterations = $2,
		    tool_calls = $3,
		    input_tokens = $4,
		    output_tokens = $5,
		    cost_usd_micros = $6,
		    error = $7,
		    finished_at = $8
		WHERE id = $9;
	`, status, iterations, toolCalls, inputTokens, outputTokens, costUSDMicros, errStr, &now, runID)
	return err
}

// GetAgentRun retrieves an agent run record ensuring tenant isolation.
func (s *Store) GetAgentRun(ctx context.Context, orgID, runID string) (*AgentRun, error) {
	var r AgentRun
	err := s.Pool.QueryRow(ctx, `
		SELECT ar.id, ar.scan_id, ar.finding_id, ar.agent, ar.provider, ar.model, ar.is_mock,
		       ar.status, ar.iterations, ar.tool_calls, ar.input_tokens, ar.output_tokens,
		       ar.cost_usd_micros, ar.error, ar.started_at, ar.finished_at
		FROM agent_runs ar
		JOIN scans s ON s.id = ar.scan_id
		JOIN projects p ON p.id = s.project_id
		WHERE ar.id = $1 AND p.organization_id = $2;
	`, runID, orgID).Scan(
		&r.ID, &r.ScanID, &r.FindingID, &r.Agent, &r.Provider, &r.Model, &r.IsMock,
		&r.Status, &r.Iterations, &r.ToolCalls, &r.InputTokens, &r.OutputTokens,
		&r.CostUSDMicros, &r.Error, &r.StartedAt, &r.FinishedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAgentRunNotFound
		}
		return nil, fmt.Errorf("get agent run: %w", err)
	}
	return &r, nil
}

// ListAgentRuns retrieves all agent runs for a scan.
func (s *Store) ListAgentRuns(ctx context.Context, orgID, scanID string) ([]AgentRun, error) {
	if err := s.VerifyScanAccess(ctx, orgID, scanID); err != nil {
		return nil, err
	}

	rows, err := s.Pool.Query(ctx, `
		SELECT id, scan_id, finding_id, agent, provider, model, is_mock,
		       status, iterations, tool_calls, input_tokens, output_tokens,
		       cost_usd_micros, error, started_at, finished_at
		FROM agent_runs
		WHERE scan_id = $1
		ORDER BY started_at DESC;
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("list agent runs: %w", err)
	}
	defer rows.Close()

	var runs []AgentRun
	for rows.Next() {
		var r AgentRun
		if err := rows.Scan(
			&r.ID, &r.ScanID, &r.FindingID, &r.Agent, &r.Provider, &r.Model, &r.IsMock,
			&r.Status, &r.Iterations, &r.ToolCalls, &r.InputTokens, &r.OutputTokens,
			&r.CostUSDMicros, &r.Error, &r.StartedAt, &r.FinishedAt,
		); err != nil {
			return nil, fmt.Errorf("scan agent run row: %w", err)
		}
		runs = append(runs, r)
	}
	return runs, nil
}

// CreateAIAnalysis stores structured analysis output with cited evidence IDs.
func (s *Store) CreateAIAnalysis(ctx context.Context, a *AIAnalysis) error {
	var outBytes []byte
	if len(a.Output) > 0 {
		outBytes = a.Output
	} else {
		outBytes = []byte("{}")
	}

	return s.Pool.QueryRow(ctx, `
		INSERT INTO ai_analyses (
			agent_run_id, scan_id, finding_id, kind, output,
			cited_evidence_ids, schema_version
		) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
		RETURNING id, created_at;
	`,
		a.AgentRunID, a.ScanID, a.FindingID, a.Kind, outBytes,
		a.CitedEvidenceIDs, a.SchemaVersion,
	).Scan(&a.ID, &a.CreatedAt)
}

// GetAIAnalysis retrieves an AI analysis record with linked cited evidence items.
func (s *Store) GetAIAnalysis(ctx context.Context, orgID, analysisID string) (*AIAnalysis, error) {
	var a AIAnalysis
	var outBytes []byte
	err := s.Pool.QueryRow(ctx, `
		SELECT an.id, an.agent_run_id, an.scan_id, an.finding_id, an.kind, an.output,
		       an.cited_evidence_ids, an.schema_version, an.created_at
		FROM ai_analyses an
		JOIN scans s ON s.id = an.scan_id
		JOIN projects p ON p.id = s.project_id
		WHERE an.id = $1 AND p.organization_id = $2;
	`, analysisID, orgID).Scan(
		&a.ID, &a.AgentRunID, &a.ScanID, &a.FindingID, &a.Kind, &outBytes,
		&a.CitedEvidenceIDs, &a.SchemaVersion, &a.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAIAnalysisNotFound
		}
		return nil, fmt.Errorf("get ai analysis: %w", err)
	}
	a.Output = json.RawMessage(outBytes)

	// Fetch cited evidence details
	if len(a.CitedEvidenceIDs) > 0 {
		rows, err := s.Pool.Query(ctx, `
			SELECT id, scan_id, finding_id, artifact_sha256, evidence_type, location,
			       line_start, line_end, byte_offset, excerpt, rule_id, analysis_source,
			       tool_name, tool_version, confidence, verification_status, redaction, provenance, collected_at
			FROM evidence
			WHERE id = ANY($1)
			ORDER BY collected_at ASC;
		`, a.CitedEvidenceIDs)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var ev EvidenceItem
				var redactionBytes, provenanceBytes []byte
				if err := rows.Scan(
					&ev.ID, &ev.ScanID, &ev.FindingID, &ev.ArtifactSHA256, &ev.EvidenceType,
					&ev.Location, &ev.LineStart, &ev.LineEnd, &ev.ByteOffset, &ev.Excerpt,
					&ev.RuleID, &ev.AnalysisSource, &ev.ToolName, &ev.ToolVersion,
					&ev.Confidence, &ev.VerificationStatus, &redactionBytes, &provenanceBytes,
					&ev.CollectedAt,
				); err == nil {
					ev.Redaction = json.RawMessage(redactionBytes)
					ev.Provenance = json.RawMessage(provenanceBytes)
					a.CitedEvidence = append(a.CitedEvidence, ev)
				}
			}
		}
	}

	return &a, nil
}

// ListAIAnalyses retrieves analyses for a scan and optional finding.
func (s *Store) ListAIAnalyses(ctx context.Context, orgID, scanID string, findingID *string) ([]AIAnalysis, error) {
	if err := s.VerifyScanAccess(ctx, orgID, scanID); err != nil {
		return nil, err
	}

	query := `
		SELECT an.id, an.agent_run_id, an.scan_id, an.finding_id, an.kind, an.output,
		       an.cited_evidence_ids, an.schema_version, an.created_at
		FROM ai_analyses an
		WHERE an.scan_id = $1
	`
	args := []any{scanID}
	if findingID != nil && *findingID != "" {
		query += " AND an.finding_id = $2"
		args = append(args, *findingID)
	}
	query += " ORDER BY an.created_at DESC;"

	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list ai analyses: %w", err)
	}
	defer rows.Close()

	var list []AIAnalysis
	for rows.Next() {
		var a AIAnalysis
		var outBytes []byte
		if err := rows.Scan(
			&a.ID, &a.AgentRunID, &a.ScanID, &a.FindingID, &a.Kind, &outBytes,
			&a.CitedEvidenceIDs, &a.SchemaVersion, &a.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan ai analysis row: %w", err)
		}
		a.Output = json.RawMessage(outBytes)
		list = append(list, a)
	}
	return list, nil
}
