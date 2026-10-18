package ai

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/tetraneurons/reversebug/api/internal/storage"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

type ToolRegistry struct {
	store   *store.Store
	storage storage.Storage
}

func NewToolRegistry(st *store.Store, stg storage.Storage) *ToolRegistry {
	return &ToolRegistry{store: st, storage: stg}
}

type QueryEvidenceInput struct {
	FindingID string `json:"finding_id"`
}

type QueryEvidenceOutput struct {
	FindingID string               `json:"finding_id"`
	Count     int                  `json:"count"`
	Items     []store.EvidenceItem `json:"items"`
}

func (tr *ToolRegistry) QueryEvidence(ctx context.Context, orgID string, in QueryEvidenceInput) (*QueryEvidenceOutput, error) {
	finding, err := tr.store.GetFinding(ctx, orgID, in.FindingID)
	if err != nil {
		return nil, fmt.Errorf("finding not found: %w", err)
	}

	return &QueryEvidenceOutput{
		FindingID: in.FindingID,
		Count:     len(finding.Evidence),
		Items:     finding.Evidence,
	}, nil
}

type InspectSourceInput struct {
	ScanID    string `json:"scan_id"`
	FilePath  string `json:"file_path"`
	LineStart *int   `json:"line_start,omitempty"`
	LineEnd   *int   `json:"line_end,omitempty"`
}

type InspectSourceOutput struct {
	FilePath    string `json:"file_path"`
	Content     string `json:"content"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end"`
	TotalLines  int    `json:"total_lines"`
	IsTruncated bool   `json:"is_truncated"`
}

func (tr *ToolRegistry) InspectSource(ctx context.Context, orgID string, in InspectSourceInput) (*InspectSourceOutput, error) {
	storageKey, _, _, err := tr.store.GetScanArtifactStorageKey(ctx, orgID, in.ScanID)
	if err != nil {
		return nil, err
	}

	localPath, err := tr.storage.LocalPath(storageKey)
	if err != nil {
		return nil, err
	}

	zr, err := zip.OpenReader(localPath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()

	cleanReq := path.Clean(strings.TrimPrefix(in.FilePath, "/"))
	var targetFile *zip.File
	for _, f := range zr.File {
		if f.Name == cleanReq || strings.TrimPrefix(f.Name, "/") == cleanReq {
			targetFile = f
			break
		}
	}

	if targetFile == nil {
		return &InspectSourceOutput{
			FilePath: cleanReq,
			Content:  fmt.Sprintf("// File %s not found in APK archive", cleanReq),
		}, nil
	}

	rc, err := targetFile.Open()
	if err != nil {
		return nil, fmt.Errorf("open archive entry: %w", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, 1*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	total := len(lines)

	start := 1
	if in.LineStart != nil && *in.LineStart > 0 && *in.LineStart <= total {
		start = *in.LineStart
	}
	end := total
	if in.LineEnd != nil && *in.LineEnd >= start && *in.LineEnd <= total {
		end = *in.LineEnd
	} else if in.LineStart != nil {
		// Window of 20 lines
		end = start + 20
		if end > total {
			end = total
		}
	}

	subLines := lines[start-1 : end]
	return &InspectSourceOutput{
		FilePath:   cleanReq,
		Content:    strings.Join(subLines, "\n"),
		LineStart:  start,
		LineEnd:    end,
		TotalLines: total,
	}, nil
}

type CheckReachabilityInput struct {
	ScanID        string `json:"scan_id"`
	ComponentName string `json:"component_name"`
}

type CheckReachabilityOutput struct {
	ComponentName string   `json:"component_name"`
	IsExported    bool     `json:"is_exported"`
	Permission    *string  `json:"permission"`
	Reachability  string   `json:"reachability"`
	AttackPath    []string `json:"attack_path"`
}

func (tr *ToolRegistry) CheckReachability(ctx context.Context, orgID string, in CheckReachabilityInput) (*CheckReachabilityOutput, error) {
	graph, err := tr.store.GetEvidenceGraph(ctx, orgID, in.ScanID)
	if err != nil {
		return nil, err
	}

	isExported := false
	var perm *string
	shortName := in.ComponentName
	if idx := strings.LastIndex(in.ComponentName, "."); idx != -1 {
		shortName = in.ComponentName[idx+1:]
	}

	for _, n := range graph.Nodes {
		if strings.Contains(n.Label, shortName) || strings.Contains(n.NodeKey, shortName) {
			if n.NodeType == "entry_point" {
				isExported = true
			}
			var props map[string]any
			if len(n.Properties) > 0 {
				_ = json.Unmarshal(n.Properties, &props)
				if exp, ok := props["exported"].(bool); ok && exp {
					isExported = true
				}
				if p, ok := props["permission"].(string); ok && p != "" {
					perm = &p
				}
			}
		}
	}

	reachability := "unreachable"
	attackPath := []string{"External App / Adversary Intent"}
	if isExported && perm == nil {
		reachability = "reachable"
		attackPath = append(attackPath, "No android:permission restriction on exported component", in.ComponentName)
	} else if isExported && perm != nil {
		reachability = "conditional"
		attackPath = append(attackPath, fmt.Sprintf("Restricted by signature/system permission %q", *perm), in.ComponentName)
	} else {
		attackPath = append(attackPath, "Component is not exported (android:exported=\"false\")", "Local process only")
	}

	return &CheckReachabilityOutput{
		ComponentName: in.ComponentName,
		IsExported:    isExported,
		Permission:    perm,
		Reachability:  reachability,
		AttackPath:    attackPath,
	}, nil
}

type ExplainRuleInput struct {
	RuleID string `json:"rule_id"`
}

type ExplainRuleOutput struct {
	RuleID         string   `json:"rule_id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	MASVSCategory  string   `json:"masvs_category"`
	RemediationTip string   `json:"remediation_tip"`
	ReferenceDocs  []string `json:"reference_docs"`
}

func (tr *ToolRegistry) ExplainRule(ruleID string) *ExplainRuleOutput {
	rules := map[string]ExplainRuleOutput{
		"RB-COMP-001": {
			RuleID:         "RB-COMP-001",
			Title:          "Unprotected Exported Activity",
			Description:    "Activities exported without signature permission allow unauthorized local applications or malicious apps to launch internal application flows.",
			Severity:       "high",
			MASVSCategory:  "MASVS-PLATFORM-1",
			RemediationTip: "Set android:exported=\"false\" or apply android:permission=\"signature\" in AndroidManifest.xml.",
			ReferenceDocs:  []string{"https://developer.android.com/guide/topics/manifest/activity-element#exported"},
		},
		"RB-COMP-002": {
			RuleID:         "RB-COMP-002",
			Title:          "Unprotected Exported BroadcastReceiver",
			Description:    "Exported BroadcastReceivers can receive unsolicited intents from any app, risking spoofed push notifications or state tampering.",
			Severity:       "high",
			MASVSCategory:  "MASVS-PLATFORM-1",
			RemediationTip: "Set android:exported=\"false\" or enforce signature permissions on intent broadcasts.",
			ReferenceDocs:  []string{"https://developer.android.com/guide/components/broadcasts"},
		},
		"RB-MANIFEST-DEBUGGABLE": {
			RuleID:         "RB-MANIFEST-DEBUGGABLE",
			Title:          "Application is Debuggable in Production",
			Description:    "android:debuggable=\"true\" enables JDWP debugger connection, granting full memory inspection and arbitrary code execution.",
			Severity:       "critical",
			MASVSCategory:  "MASVS-RESILIENCE-1",
			RemediationTip: "Ensure android:debuggable is false in release builds (set buildType.release.debuggable = false).",
			ReferenceDocs:  []string{"https://cwe.mitre.org/data/definitions/215.html"},
		},
		"RB-MANIFEST-BACKUP": {
			RuleID:         "RB-MANIFEST-BACKUP",
			Title:          "Application Backup Allowed",
			Description:    "android:allowBackup=\"true\" allows adb backup extraction of private sandbox storage including SQLite databases and SharedPreferences.",
			Severity:       "medium",
			MASVSCategory:  "MASVS-STORAGE-2",
			RemediationTip: "Set android:allowBackup=\"false\" or define a selective fullBackupContent XML filter.",
			ReferenceDocs:  []string{"https://developer.android.com/guide/topics/data/autobackup"},
		},
		"RB-NET-CLEARTEXT": {
			RuleID:         "RB-NET-CLEARTEXT",
			Title:          "Cleartext HTTP Traffic Permitted",
			Description:    "android:usesCleartextTraffic=\"true\" permits unencrypted HTTP transmission, vulnerable to active MITM interception.",
			Severity:       "high",
			MASVSCategory:  "MASVS-NETWORK-1",
			RemediationTip: "Enforce HTTPS throughout and configure network_security_config.xml with cleartextTrafficPermitted=\"false\".",
			ReferenceDocs:  []string{"https://developer.android.com/privacy-and-security/security-config"},
		},
		"RB-SEC-001": {
			RuleID:         "RB-SEC-001",
			Title:          "Hardcoded Cloud / API Credential Disclosed",
			Description:    "Embedded API tokens or private keys are trivially extractable from decompiled bytecode and strings.xml.",
			Severity:       "critical",
			MASVSCategory:  "MASVS-STORAGE-1",
			RemediationTip: "Revoke the exposed key immediately and fetch ephemeral tokens through an authenticated backend service.",
			ReferenceDocs:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
	}

	if r, ok := rules[ruleID]; ok {
		return &r
	}
	return &ExplainRuleOutput{
		RuleID:         ruleID,
		Title:          "Android Security Finding",
		Description:    "Standard security rule evaluating Android application security posture.",
		Severity:       "medium",
		MASVSCategory:  "MASVS-GENERAL",
		RemediationTip: "Review component configuration and apply least privilege principles.",
		ReferenceDocs:  []string{"https://owasp.org/www-project-mobile-app-security/"},
	}
}
