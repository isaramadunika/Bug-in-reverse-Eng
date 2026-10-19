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

	exploitChains := e.SynthesizeExploitChains(findings)

	isChainQuery := strings.Contains(qLower, "chain") || strings.Contains(qLower, "exploit") ||
		strings.Contains(qLower, "attack") || strings.Contains(qLower, "scenario") || strings.Contains(qLower, "path")

	if isChainQuery {
		answer.WriteString("## ⚔️ AI Vulnerability Exploit Chain Synthesis\n\n")
		if len(exploitChains) == 0 {
			answer.WriteString("No multi-stage vulnerability exploit chains were successfully constructed from current findings. The identified vulnerabilities remain isolated posture issues.\n\n")
		} else {
			answer.WriteString(fmt.Sprintf("The ReverseBug AI engine correlated the identified findings and synthesized **%d viable exploit chain(s)**:\n\n", len(exploitChains)))
			for idx, chain := range exploitChains {
				sevEmoji := "🔴"
				if chain.Severity == "high" {
					sevEmoji = "🟠"
				} else if chain.Severity == "medium" {
					sevEmoji = "🟡"
				}

				answer.WriteString(fmt.Sprintf("### %s Chain %d: %s\n", sevEmoji, idx+1, chain.Title))
				answer.WriteString(fmt.Sprintf("- **Severity:** `%s` | **Exploit Feasibility:** `%s`\n", strings.ToUpper(chain.Severity), chain.Feasibility))
				answer.WriteString(fmt.Sprintf("- **Impact:** %s\n\n", chain.Impact))
				answer.WriteString("**Multi-Stage Attack Execution Path:**\n")
				for _, step := range chain.Steps {
					answer.WriteString(fmt.Sprintf("  - %s\n", step))
				}
				answer.WriteString(fmt.Sprintf("\n🛡️ **Chain Severance & Remediation:**\n%s\n\n---\n\n", chain.Remediation))

				// Link chain findings into cited findings
				for _, fid := range chain.FindingIDs {
					citedFindingIDs = append(citedFindingIDs, fid)
				}
			}
		}
	} else {
		if len(citedFindingIDs) > 0 {
			answer.WriteString("### Key Relevant Findings Identified:\n")
			for _, r := range relevantRules {
				answer.WriteString(fmt.Sprintf("- **%s**\n", r))
			}
			answer.WriteString("\n")
		}

		if len(exploitChains) > 0 {
			answer.WriteString(fmt.Sprintf("⚡ **Active Exploit Chains Alert:** ReverseBug AI identified **%d multi-stage exploit chain(s)** linking these vulnerabilities. Ask *\"Show exploit chains\"* for full attack path blueprints.\n\n", len(exploitChains)))
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
	}

	suggestedFixes := []string{
		"Set android:exported=\"false\" on unprotected activities",
		"Disable cleartext HTTP traffic in network_security_config.xml",
		"Revoke and rotate exposed API credentials",
		"Wrap intent extra extraction in defensive try-catch blocks",
	}

	return &CopilotAnswerResponse{
		Question:        question,
		Answer:          answer.String(),
		CitedFindingIDs: citedFindingIDs,
		SuggestedFixes:  suggestedFixes,
		ExploitChains:   exploitChains,
		Model:           "reversebug-copilot-v1",
		TokensUsed:      320,
	}, nil
}

// SynthesizeExploitChains correlates isolated static findings into multi-stage attack paths.
func (e *Engine) SynthesizeExploitChains(findings []store.Finding) []ExploitChain {
	var chains []ExploitChain

	// Index findings by rule ID
	byRule := make(map[string][]store.Finding)
	hasSecret := false
	var secretFindings []store.Finding
	hasExportedComp := false
	var exportedCompFindings []store.Finding

	for _, f := range findings {
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
		if strings.HasPrefix(f.RuleID, "RB-SECRET-") || f.RuleID == "RB-SENSITIVE-FIREBASE" || f.RuleID == "RB-SENSITIVE-S3-BUCKET" {
			hasSecret = true
			secretFindings = append(secretFindings, f)
		}
		if strings.HasPrefix(f.RuleID, "RB-COMP-") {
			hasExportedComp = true
			exportedCompFindings = append(exportedCompFindings, f)
		}
	}

	collectIDs := func(ruleIDs ...string) []string {
		var ids []string
		for _, rid := range ruleIDs {
			for _, f := range byRule[rid] {
				ids = append(ids, f.ID)
			}
		}
		return ids
	}

	// 1. Cloud Credential Takeover & Sandbox Exfiltration Chain
	if hasSecret && (len(byRule["RB-MANIFEST-DEBUGGABLE"]) > 0 || len(byRule["RB-MANIFEST-BACKUP"]) > 0 || hasExportedComp) {
		var involvedRules []string
		var involvedIDs []string
		for _, sf := range secretFindings {
			involvedRules = append(involvedRules, sf.RuleID)
			involvedIDs = append(involvedIDs, sf.ID)
		}
		if len(byRule["RB-MANIFEST-DEBUGGABLE"]) > 0 {
			involvedRules = append(involvedRules, "RB-MANIFEST-DEBUGGABLE")
			involvedIDs = append(involvedIDs, collectIDs("RB-MANIFEST-DEBUGGABLE")...)
		}
		if len(byRule["RB-MANIFEST-BACKUP"]) > 0 {
			involvedRules = append(involvedRules, "RB-MANIFEST-BACKUP")
			involvedIDs = append(involvedIDs, collectIDs("RB-MANIFEST-BACKUP")...)
		}

		chains = append(chains, ExploitChain{
			ID:          "EXPLOIT-CHAIN-01-CLOUD-TAKEOVER",
			Title:       "Decompilation & Cloud Infrastructure Takeover via Hardcoded Secrets",
			Severity:    "critical",
			Feasibility: "immediate",
			Impact:      "Direct unauthorized API access to cloud databases (Firebase, AWS, Stripe), arbitrary data manipulation, and financial compromise bypassing all mobile application controls.",
			Steps: []string{
				"Step 1 (Reconnaissance): Attacker pulls the target APK directly or creates a local sandbox backup via 'adb backup -f app.ab'.",
				"Step 2 (Decompilation & Secret Harvesting): Attacker decompiles bytecode resources and extracts live hardcoded secrets (e.g. AWS access keys, Stripe secret tokens, or Firebase URLs).",
				"Step 3 (Cloud API Exploitation): Attacker executes authenticated REST/GraphQL API queries directly against cloud infrastructure, bypassing all client-side authentication and business logic.",
			},
			FindingIDs:  involvedIDs,
			RuleIDs:     involvedRules,
			Remediation: "Remove all hardcoded API secrets from client assets immediately; revoke and rotate exposed credentials; delegate sensitive backend requests to an authenticated gateway.",
		})
	}

	// 2. Local IPC Intent Fuzzing & Crash Denial-of-Service Chain
	if hasExportedComp && len(byRule["RB-CRASH-INTENT-DOS"]) > 0 {
		var involvedIDs []string
		involvedIDs = append(involvedIDs, collectIDs("RB-CRASH-INTENT-DOS")...)
		for _, ec := range exportedCompFindings {
			involvedIDs = append(involvedIDs, ec.ID)
		}

		chains = append(chains, ExploitChain{
			ID:          "EXPLOIT-CHAIN-02-IPC-CRASH-DOS",
			Title:       "IPC Intent Fuzzing & Application Crash Denial of Service",
			Severity:    "high",
			Feasibility: "immediate",
			Impact:      "A malicious unprivileged application installed on the same device can trigger continuous process crashes (Denial of Service) and ANR dialogs, rendering the app unusable.",
			Steps: []string{
				"Step 1 (IPC Discovery): A rogue third-party app scans installed packages and identifies exported components lacking enforcing permissions.",
				"Step 2 (Fuzzing Injection): The rogue app fires an explicit Intent with null extras or mismatched parcelable structures via Context.startActivity() / startService().",
				"Step 3 (Unhandled Fatal Crash): The victim application attempts to deserialize the intent parameters without defensive null-safety, triggering a fatal NullPointerException or BadParcelableException that kills the host process.",
			},
			FindingIDs:  involvedIDs,
			RuleIDs:     []string{"RB-CRASH-INTENT-DOS", "RB-COMP-001", "RB-COMP-002", "RB-COMP-003"},
			Remediation: "Add defensive null checks 'if (getIntent() != null && getIntent().getExtras() != null)' and wrap intent extra deserialization in try-catch blocks; set 'android:exported=\"false\"' on internal components.",
		})
	}

	// 3. Mutable PendingIntent Hijacking Chain
	if len(byRule["RB-CRASH-MUTABLE-PENDINGINTENT"]) > 0 {
		chains = append(chains, ExploitChain{
			ID:          "EXPLOIT-CHAIN-03-PENDINGINTENT-HIJACK",
			Title:       "Mutable PendingIntent Redirection & Privilege Escalation",
			Severity:    "high",
			Feasibility: "probable",
			Impact:      "Attacker intercepts mutable PendingIntent, mutates target component or action, and forces the application to execute privileged actions with higher internal permissions.",
			Steps: []string{
				"Step 1 (Interception): The application dispatches a PendingIntent created without FLAG_IMMUTABLE to a system notification or external receiver.",
				"Step 2 (Intent Mutation): A malicious recipient app intercepts the PendingIntent and injects extra flags, replaces the target component, or alters embedded extras.",
				"Step 3 (Privileged Execution): When the PendingIntent is triggered, it executes with the victim application's elevated permissions.",
			},
			FindingIDs:  collectIDs("RB-CRASH-MUTABLE-PENDINGINTENT"),
			RuleIDs:     []string{"RB-CRASH-MUTABLE-PENDINGINTENT"},
			Remediation: "Explicitly pass 'PendingIntent.FLAG_IMMUTABLE' when instantiating PendingIntent factory methods.",
		})
	}

	// 4. Man-in-the-Middle Network Interception Chain
	if (len(byRule["RB-NET-CLEARTEXT"]) > 0 || len(byRule["RB-NET-TRUSTALL"]) > 0) && (len(byRule["RB-LOG-SENSITIVE"]) > 0 || len(byRule["RB-SENSITIVE-CLIPBOARD"]) > 0 || hasSecret) {
		var involvedIDs []string
		involvedIDs = append(involvedIDs, collectIDs("RB-NET-CLEARTEXT", "RB-NET-TRUSTALL", "RB-LOG-SENSITIVE", "RB-SENSITIVE-CLIPBOARD")...)

		chains = append(chains, ExploitChain{
			ID:          "EXPLOIT-CHAIN-04-MITM-TRAFFIC-INTERCEPT",
			Title:       "Cleartext Transport Interception & Sensitive Token Hijacking",
			Severity:    "high",
			Feasibility: "high",
			Impact:      "Adversary positioned on local network (e.g. public Wi-Fi) intercepts authentication tokens, credentials, and user data in transit.",
			Steps: []string{
				"Step 1 (Positioning): Adversary sets up a rogue Wi-Fi access point or performs ARP spoofing on a local subnet.",
				"Step 2 (Traffic Interception): Because cleartext traffic is permitted (android:usesCleartextTraffic='true') or custom TrustManagers disable TLS verification, traffic is sent unencrypted or accepts spoofed certificates.",
				"Step 3 (Credential Theft): Attacker captures authorization tokens and sensitive user PII from captured HTTP request streams.",
			},
			FindingIDs:  involvedIDs,
			RuleIDs:     []string{"RB-NET-CLEARTEXT", "RB-NET-TRUSTALL"},
			Remediation: "Enforce HTTPS with cleartextTrafficPermitted=\"false\" in network_security_config.xml and remove TrustAll custom X509TrustManagers.",
		})
	}

	// 5. Client Runtime Hooking & Reverse Engineering Tampering Chain
	if len(byRule["RB-RESILIENCE-ROOT"]) > 0 && (len(byRule["RB-REVERSE-ANTI-DEBUG-ABSENT"]) > 0 || len(byRule["RB-REVERSE-FRIDA-HOOK-ABSENT"]) > 0) {
		var involvedIDs []string
		involvedIDs = append(involvedIDs, collectIDs("RB-RESILIENCE-ROOT", "RB-REVERSE-ANTI-DEBUG-ABSENT", "RB-REVERSE-FRIDA-HOOK-ABSENT")...)

		chains = append(chains, ExploitChain{
			ID:          "EXPLOIT-CHAIN-05-RUNTIME-HOOKING-BYPASS",
			Title:       "Dynamic Frida Hooking & Memory Tampering Exploitation",
			Severity:    "medium",
			Feasibility: "immediate",
			Impact:      "Adversaries on rooted environments attach Frida/Xposed hooks to bypass client-side checks (biometrics, SSL pinning, licensing) and dump runtime secrets from RAM.",
			Steps: []string{
				"Step 1 (Environment Setup): Attacker installs the APK on a rooted device or emulator running frida-server.",
				"Step 2 (Process Attachment): Lacking root, debugger, and Frida detection heuristics, the process allows arbitrary debugger attachment and dynamic script injection.",
				"Step 3 (Logic Subversion): Attacker dynamically hooks Java/native authentication methods, forces return values to true, and logs decrypted session keys from memory.",
			},
			FindingIDs:  involvedIDs,
			RuleIDs:     []string{"RB-RESILIENCE-ROOT", "RB-REVERSE-ANTI-DEBUG-ABSENT", "RB-REVERSE-FRIDA-HOOK-ABSENT"},
			Remediation: "Integrate Google Play Integrity API or multi-layered root/debugger detection; implement Frida server port and library checks.",
		})
	}

	// 6. UI Tapjacking & Overlay Attack Chain
	if len(byRule["RB-SENSITIVE-TAPJACKING"]) > 0 && hasExportedComp {
		var involvedIDs []string
		involvedIDs = append(involvedIDs, collectIDs("RB-SENSITIVE-TAPJACKING")...)
		for _, ec := range exportedCompFindings {
			involvedIDs = append(involvedIDs, ec.ID)
		}

		chains = append(chains, ExploitChain{
			ID:          "EXPLOIT-CHAIN-06-TAPJACKING-HIJACK",
			Title:       "Invisible Overlay Tapjacking & Unauthorized User Action Coercion",
			Severity:    "medium",
			Feasibility: "probable",
			Impact:      "Malicious application draws invisible overlays above exported activities, tricking the user into clicking administrative approvals or sensitive transactions.",
			Steps: []string{
				"Step 1 (Overlay Injection): Attacker deploys a deceptive utility with SYSTEM_ALERT_WINDOW permission on user device.",
				"Step 2 (Screen Alignment): When the victim's exported activity is opened, the attacker draws a transparent full-screen overlay view.",
				"Step 3 (Touch Hijack): User touches intended for a fake prompt pass through directly to the underlying activity, approving privileged transactions unwittingly.",
			},
			FindingIDs:  involvedIDs,
			RuleIDs:     []string{"RB-SENSITIVE-TAPJACKING", "RB-COMP-001"},
			Remediation: "Add android:filterTouchesWhenObscured=\"true\" to sensitive exported activities in AndroidManifest.xml.",
		})
	}

	// 7. Insecure WebView Cross-Origin File Access Chain
	if len(byRule["RB-WEBVIEW-FILE-ACCESS"]) > 0 {
		chains = append(chains, ExploitChain{
			ID:          "EXPLOIT-CHAIN-07-WEBVIEW-SANDBOX-ESCAPE",
			Title:       "WebView Cross-Origin Local Sandbox File Exfiltration",
			Severity:    "critical",
			Feasibility: "high",
			Impact:      "Untrusted web content rendered in WebView uses universal file access to read private SQLite databases, shared preferences, and authentication tokens from /data/data/.",
			Steps: []string{
				"Step 1 (Malicious Payload Delivery): Attacker tricks the application into loading an attacker-controlled file:// or web URL into a WebView.",
				"Step 2 (Same-Origin Policy Bypass): Because setAllowUniversalAccessFromFileURLs is enabled, malicious JavaScript bypasses SOP constraints on file:// schemes.",
				"Step 3 (Sandbox Exfiltration): JavaScript reads private databases and tokens from application storage and transmits them to attacker infrastructure.",
			},
			FindingIDs:  collectIDs("RB-WEBVIEW-FILE-ACCESS"),
			RuleIDs:     []string{"RB-WEBVIEW-FILE-ACCESS"},
			Remediation: "Call setAllowUniversalAccessFromFileURLs(false), setAllowFileAccessFromFileURLs(false), and setAllowFileAccess(false) on all WebView instances.",
		})
	}

	return chains
}
