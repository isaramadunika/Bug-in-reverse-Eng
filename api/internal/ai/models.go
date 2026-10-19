package ai

import (
	"encoding/json"
	"time"
)

type AgentRole string

const (
	RoleReAnalyst          AgentRole = "re_analyst"
	RoleValidationAnalyst  AgentRole = "validation_analyst"
	RoleSecretAuditor      AgentRole = "secret_auditor"
	RoleRiskAssessor       AgentRole = "risk_assessor"
	RoleRemediationAdvisor AgentRole = "remediation_advisor"
	RoleReportAnalyst      AgentRole = "report_analyst"
)

type AnalysisVerdict string

const (
	VerdictConfirmed          AnalysisVerdict = "confirmed"
	VerdictLikelyFalsePositive AnalysisVerdict = "likely_false_positive"
	VerdictNeedsHumanReview   AnalysisVerdict = "needs_human_review"
)

type StructuredAnalysisOutput struct {
	Verdict             AnalysisVerdict `json:"verdict"`
	Confidence          string          `json:"confidence"` // high | medium | low
	ExploitabilityScore string          `json:"exploitability_score"` // critical | high | medium | low | none
	ReachabilityProof   string          `json:"reachability_proof"`
	AttackScenario      string          `json:"attack_scenario"`
	RemediationDiff     string          `json:"remediation_diff"`
	ExecutiveSummary    string          `json:"executive_summary"`
	TechnicalExplanation string         `json:"technical_explanation"`
	CitedEvidenceIDs    []string        `json:"cited_evidence_ids"`
}

type ToolCallRecord struct {
	ToolName   string          `json:"tool_name"`
	Input      json.RawMessage `json:"input"`
	Output     json.RawMessage `json:"output"`
	DurationMS int64           `json:"duration_ms"`
}

type AgentExecutionResult struct {
	RunID            string                   `json:"run_id"`
	Agent            AgentRole                `json:"agent"`
	Provider         string                   `json:"provider"`
	Model            string                   `json:"model"`
	IsMock           bool                     `json:"is_mock"`
	Status           string                   `json:"status"`
	Iterations       int                      `json:"iterations"`
	ToolCalls        int                      `json:"tool_calls"`
	ToolCallHistory  []ToolCallRecord         `json:"tool_call_history,omitempty"`
	InputTokens      int                      `json:"input_tokens"`
	OutputTokens     int                      `json:"output_tokens"`
	CostUSDMicros    int64                    `json:"cost_usd_micros"`
	Analysis         StructuredAnalysisOutput `json:"analysis"`
	CitedEvidenceIDs []string                 `json:"cited_evidence_ids"`
	CreatedAt        time.Time                `json:"created_at"`
}

type ExploitChain struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`    // critical | high | medium | low
	Feasibility string   `json:"feasibility"` // immediate | high | probable | theoretical
	Impact      string   `json:"impact"`
	Steps       []string `json:"steps"`
	FindingIDs  []string `json:"finding_ids"`
	RuleIDs     []string `json:"rule_ids"`
	Remediation string   `json:"remediation"`
}

type CopilotQuestionRequest struct {
	Question string `json:"question"`
}

type CopilotAnswerResponse struct {
	Question        string         `json:"question"`
	Answer          string         `json:"answer"`
	CitedFindingIDs []string       `json:"cited_finding_ids,omitempty"`
	SuggestedFixes  []string       `json:"suggested_fixes,omitempty"`
	ExploitChains   []ExploitChain `json:"exploit_chains,omitempty"`
	Model           string         `json:"model"`
	TokensUsed      int            `json:"tokens_used"`
}
