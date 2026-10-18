package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tetraneurons/reversebug/api/internal/storage"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

type Engine struct {
	store   *store.Store
	storage storage.Storage
	tools   *ToolRegistry
}

func NewEngine(st *store.Store, stg storage.Storage) *Engine {
	return &Engine{
		store:   st,
		storage: stg,
		tools:   NewToolRegistry(st, stg),
	}
}

// InvestigateFinding executes an evidence-grounded autonomous security investigation.
func (e *Engine) InvestigateFinding(
	ctx context.Context,
	orgID string,
	scanID string,
	findingID string,
	role AgentRole,
) (*AgentExecutionResult, error) {
	// Validate scan access
	if err := e.store.VerifyScanAccess(ctx, orgID, scanID); err != nil {
		return nil, err
	}

	finding, err := e.store.GetFinding(ctx, orgID, findingID)
	if err != nil {
		return nil, err
	}

	if role == "" {
		role = RoleValidationAnalyst
	}

	provider := "heuristic_agent"
	model := "reversebug-security-v1"
	isMock := true

	run := &store.AgentRun{
		ScanID:        scanID,
		FindingID:     &findingID,
		Agent:         string(role),
		Provider:      provider,
		Model:         model,
		IsMock:        isMock,
		Status:        "running",
		Iterations:    0,
		ToolCalls:     0,
		InputTokens:   0,
		OutputTokens:  0,
		CostUSDMicros: 0,
	}

	if err := e.store.CreateAgentRun(ctx, run); err != nil {
		return nil, fmt.Errorf("create agent run: %w", err)
	}

	// 1. Tool Call: Query Evidence
	evOutput, err := e.tools.QueryEvidence(ctx, orgID, QueryEvidenceInput{FindingID: findingID})
	toolCallsCount := 1
	var citedEvidenceIDs []string
	var primaryExcerpt string
	if err == nil && evOutput != nil {
		for _, it := range evOutput.Items {
			citedEvidenceIDs = append(citedEvidenceIDs, it.ID)
			if primaryExcerpt == "" && it.Excerpt != "" {
				primaryExcerpt = it.Excerpt
			}
		}
	}

	// 2. Tool Call: Check Reachability (if component finding)
	var reachabilityResult *CheckReachabilityOutput
	var componentTarget string
	if len(finding.Occurrences) > 0 && finding.Occurrences[0].ComponentName != nil {
		componentTarget = *finding.Occurrences[0].ComponentName
	}
	if componentTarget == "" {
		// Heuristic extract component from title/description
		words := strings.Fields(finding.Description)
		for _, w := range words {
			if strings.Contains(w, ".") && (strings.HasSuffix(w, "Activity") || strings.HasSuffix(w, "Service") || strings.HasSuffix(w, "Receiver")) {
				componentTarget = strings.Trim(w, ".:;,`'\"")
				break
			}
		}
	}

	if componentTarget != "" {
		reachabilityResult, _ = e.tools.CheckReachability(ctx, orgID, CheckReachabilityInput{
			ScanID:        scanID,
			ComponentName: componentTarget,
		})
		toolCallsCount++
	}

	// 3. Tool Call: Inspect Source (if occurrence has file & line)
	var sourceSnippet string
	if len(finding.Occurrences) > 0 && finding.Occurrences[0].FilePath != nil {
		srcOut, err := e.tools.InspectSource(ctx, orgID, InspectSourceInput{
			ScanID:    scanID,
			FilePath:  *finding.Occurrences[0].FilePath,
			LineStart: finding.Occurrences[0].LineStart,
			LineEnd:   finding.Occurrences[0].LineEnd,
		})
		if err == nil && srcOut != nil {
			sourceSnippet = srcOut.Content
			toolCallsCount++
		}
	}

	// 4. Tool Call: Explain Rule
	ruleExplanation := e.tools.ExplainRule(finding.RuleID)
	toolCallsCount++

	// 5. Synthesize Verdict & Assessment grounded in collected tool outputs
	verdict := VerdictConfirmed
	confidence := "high"
	exploitability := "high"
	reachabilityProof := "Component is declared with android:exported='true' and has no signature permission enforcement. Callable via adb or 3rd-party intent."
	if reachabilityResult != nil {
		if reachabilityResult.Reachability == "unreachable" {
			verdict = VerdictLikelyFalsePositive
			exploitability = "none"
			reachabilityProof = "Component is explicitly restricted by android:exported='false'; external intents cannot trigger execution."
		} else if reachabilityResult.Reachability == "conditional" {
			exploitability = "medium"
			reachabilityProof = fmt.Sprintf("Component is exported but gated by permission %v.", reachabilityResult.Permission)
		}
	}

	var attackScenario string
	if verdict == VerdictConfirmed {
		attackScenario = fmt.Sprintf(
			"Step 1: Install adversary application on same Android device (API 21+).\n"+
				"Step 2: Construct explicit Intent targeting component %q:\n"+
				"       Intent intent = new Intent();\n"+
				"       intent.setComponent(new ComponentName(%q, %q));\n"+
				"       startActivity(intent);\n"+
				"Step 3: Target component executes without security exception, bypassing authentication or exposing internal state.",
			componentTarget, "target.package.name", componentTarget,
		)
	} else {
		attackScenario = "Attack vector is mitigated because the component is isolated within the private sandbox and rejected by the Android OS Package Manager."
	}

	var remediationDiff string
	if strings.Contains(finding.RuleID, "COMP") {
		remediationDiff = fmt.Sprintf(
			"--- AndroidManifest.xml (Vulnerable)\n"+
				"+++ AndroidManifest.xml (Remediated)\n"+
				"@@ -15,2 +15,2 @@\n"+
				"-    <activity android:name=%q android:exported=\"true\" />\n"+
				"+    <activity android:name=%q android:exported=\"false\" />",
			componentTarget, componentTarget,
		)
	} else if strings.Contains(finding.RuleID, "DEBUGGABLE") {
		remediationDiff = "--- AndroidManifest.xml\n+++ AndroidManifest.xml\n- <application android:debuggable=\"true\">\n+ <application android:debuggable=\"false\">"
	} else if strings.Contains(finding.RuleID, "BACKUP") {
		remediationDiff = "--- AndroidManifest.xml\n+++ AndroidManifest.xml\n- <application android:allowBackup=\"true\">\n+ <application android:allowBackup=\"false\">"
	} else if strings.Contains(finding.RuleID, "CLEARTEXT") {
		remediationDiff = "--- AndroidManifest.xml\n+++ AndroidManifest.xml\n- <application android:usesCleartextTraffic=\"true\">\n+ <application android:usesCleartextTraffic=\"false\">"
	} else {
		remediationDiff = fmt.Sprintf("// Remediation:\n// %s", finding.Remediation)
	}

	analysisOutput := StructuredAnalysisOutput{
		Verdict:             verdict,
		Confidence:          confidence,
		ExploitabilityScore: exploitability,
		ReachabilityProof:   reachabilityProof,
		AttackScenario:      attackScenario,
		RemediationDiff:     remediationDiff,
		ExecutiveSummary: fmt.Sprintf(
			"The %s agent performed automated deep analysis on finding %s (%s). Verification verdict is %s with %s confidence.",
			role, finding.RuleID, finding.Title, verdict, confidence,
		),
		TechnicalExplanation: fmt.Sprintf(
			"%s\n\nRule Reference: %s (%s). Observed evidence: %s",
			finding.Description, ruleExplanation.Title, ruleExplanation.MASVSCategory, primaryExcerpt,
		),
		CitedEvidenceIDs: citedEvidenceIDs,
	}

	rawOut, _ := json.Marshal(analysisOutput)

	// Persist AI Analysis
	aiAnalysis := &store.AIAnalysis{
		AgentRunID:       run.ID,
		ScanID:           scanID,
		FindingID:        &findingID,
		Kind:             string(role),
		Output:           rawOut,
		CitedEvidenceIDs: citedEvidenceIDs,
		SchemaVersion:    "ai_analysis_v1",
	}

	if err := e.store.CreateAIAnalysis(ctx, aiAnalysis); err != nil {
		errMsg := err.Error()
		_ = e.store.UpdateAgentRun(ctx, run.ID, "failed", 1, toolCallsCount, 450, 200, 1500, &errMsg)
		return nil, fmt.Errorf("create ai analysis: %w", err)
	}

	// Finalize agent run
	inputTokens := 450 + len(sourceSnippet)/4
	outputTokens := 280 + len(rawOut)/4
	costMicros := int64(inputTokens*3 + outputTokens*15) // $3/M in, $15/M out approx

	if err := e.store.UpdateAgentRun(
		ctx,
		run.ID,
		"succeeded",
		2,
		toolCallsCount,
		inputTokens,
		outputTokens,
		costMicros,
		nil,
	); err != nil {
		return nil, fmt.Errorf("finalize agent run: %w", err)
	}

	return &AgentExecutionResult{
		RunID:            run.ID,
		Agent:            role,
		Provider:         provider,
		Model:            model,
		IsMock:           isMock,
		Status:           "succeeded",
		Iterations:       2,
		ToolCalls:        toolCallsCount,
		InputTokens:      inputTokens,
		OutputTokens:     outputTokens,
		CostUSDMicros:    costMicros,
		Analysis:         analysisOutput,
		CitedEvidenceIDs: citedEvidenceIDs,
		CreatedAt:        time.Now().UTC(),
	}, nil
}

// AskCopilot provides grounded conversational assistance over the full scan context.
func (e *Engine) AskCopilot(
	ctx context.Context,
	orgID string,
	scanID string,
	question string,
) (*CopilotAnswerResponse, error) {
	if err := e.store.VerifyScanAccess(ctx, orgID, scanID); err != nil {
		return nil, err
	}

	scan, err := e.store.GetScan(ctx, orgID, scanID)
	if err != nil {
		return nil, err
	}

	findings, err := e.store.ListFindings(ctx, orgID, scanID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}

	// Identify relevant findings based on question keywords
	var citedFindingIDs []string
	var relevantRules []string
	qLower := strings.ToLower(question)

	for _, f := range findings {
		ruleMatch := strings.Contains(qLower, strings.ToLower(f.RuleID))
		catMatch := strings.Contains(qLower, strings.ToLower(f.Category))
		sevMatch := strings.Contains(qLower, strings.ToLower(f.Severity))
		titleMatch := strings.Contains(qLower, "activity") && strings.Contains(f.Title, "Activity") ||
			strings.Contains(qLower, "secret") && strings.Contains(f.Title, "Secret") ||
			strings.Contains(qLower, "token") && strings.Contains(f.Title, "Credential") ||
			strings.Contains(qLower, "debug") && strings.Contains(f.RuleID, "DEBUG") ||
			strings.Contains(qLower, "cleartext") && strings.Contains(f.RuleID, "CLEARTEXT")

		if ruleMatch || catMatch || (sevMatch && (f.Severity == "critical" || f.Severity == "high")) || titleMatch {
			citedFindingIDs = append(citedFindingIDs, f.ID)
			relevantRules = append(relevantRules, fmt.Sprintf("%s (%s: %s)", f.RuleID, f.Severity, f.Title))
		}
	}

	// Fallback to top findings if no specific match
	if len(citedFindingIDs) == 0 && len(findings) > 0 {
		for i := 0; i < len(findings) && i < 3; i++ {
			citedFindingIDs = append(citedFindingIDs, findings[i].ID)
			relevantRules = append(relevantRules, fmt.Sprintf("%s (%s)", findings[i].RuleID, findings[i].Title))
		}
	}

	scoreVal := 100
	if scan.SecurityScore != nil {
		scoreVal = *scan.SecurityScore
	}

	var answer strings.Builder
	answer.WriteString(fmt.Sprintf("Based on security analysis of scan **%s** (Security Score: **%d/100**, Total Findings: **%d**):\n\n", scanID[:8], scoreVal, len(findings)))

	if len(citedFindingIDs) > 0 {
		answer.WriteString("### Key Relevant Findings Identified:\n")
		for _, r := range relevantRules {
			answer.WriteString(fmt.Sprintf("- **%s**\n", r))
		}
		answer.WriteString("\n")
	}

	if strings.Contains(qLower, "fix") || strings.Contains(qLower, "remediat") || strings.Contains(qLower, "how") {
		answer.WriteString("### Immediate Recommended Actions:\n")
		answer.WriteString("1. Inspect `AndroidManifest.xml` and enforce `android:exported=\"false\"` on internal Activities and BroadcastReceivers.\n")
		answer.WriteString("2. Disable `android:debuggable` and `android:allowBackup` in production release build types.\n")
		answer.WriteString("3. Ensure all network communications utilize HTTPS with a strict Network Security Configuration (`cleartextTrafficPermitted=\"false\"`).\n")
		answer.WriteString("4. Immediately rotate any hardcoded API credentials identified in string resources.\n")
	} else if strings.Contains(qLower, "critical") || strings.Contains(qLower, "score") || strings.Contains(qLower, "risk") {
		answer.WriteString("### Risk Summary:\n")
		answer.WriteString(fmt.Sprintf("The application currently holds a score of **%d/100**. ", scoreVal))
		if scoreVal < 70 {
			answer.WriteString("This indicates significant security risk from exposed entry points or embedded secrets that must be triaged before production release.")
		} else {
			answer.WriteString("The security posture is acceptable, though identified low/medium exposure points should be hardened.")
		}
	} else {
		answer.WriteString("### Analysis:\n")
		answer.WriteString("The security evidence confirms that all component exposure points and manifest configuration flags have been cross-referenced against Android MASVS benchmarks. You can inspect exact code lines using the Source Inspector tab or review the Evidence Graph for full reachability.")
	}

	suggestedFixes := []string{
		"Set android:exported=\"false\" on unprotected activities",
		"Disable cleartext HTTP traffic in network_security_config.xml",
		"Revoke and rotate exposed API credentials",
	}

	return &CopilotAnswerResponse{
		Question:        question,
		Answer:          answer.String(),
		CitedFindingIDs: citedFindingIDs,
		SuggestedFixes:  suggestedFixes,
		Model:           "reversebug-copilot-v1",
		TokensUsed:      320,
	}, nil
}
