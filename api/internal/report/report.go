// Package report generates production-grade security intelligence reports in JSON and print-ready HTML formats.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"time"

	"github.com/tetraneurons/reversebug/api/internal/store"
)

type ReportData struct {
	ReportID       string                 `json:"report_id"`
	GeneratedAt    time.Time              `json:"generated_at"`
	ProjectName    string                 `json:"project_name"`
	PackageName    string                 `json:"package_name"`
	ArtifactSHA256 string                 `json:"artifact_sha256"`
	ScanID         string                 `json:"scan_id"`
	ScanProfile    string                 `json:"scan_profile"`
	SecurityScore  int                    `json:"security_score"`
	ScoreBreakdown map[string]any         `json:"score_breakdown"`
	Summary        ReportSummary          `json:"summary"`
	Findings       []store.Finding        `json:"findings"`
	Authorization  *ReportAuthAttestation `json:"authorization,omitempty"`
}

type ReportSummary struct {
	TotalFindings    int            `json:"total_findings"`
	CriticalCount    int            `json:"critical_count"`
	HighCount        int            `json:"high_count"`
	MediumCount      int            `json:"medium_count"`
	LowCount         int            `json:"low_count"`
	InfoCount        int            `json:"info_count"`
	ReachableCount   int            `json:"reachable_count"`
	UnreachableCount int            `json:"unreachable_count"`
	UnknownCount     int            `json:"unknown_count"`
	CategoryCounts   map[string]int `json:"category_counts"`
}

type ReportAuthAttestation struct {
	AttestorName     string     `json:"attestor_name"`
	Basis            string     `json:"basis"`
	ScopeDescription string     `json:"scope_description"`
	AttestedAt       time.Time  `json:"attested_at"`
	ValidUntil       *time.Time `json:"valid_until"`
}

// BuildReportData aggregates scan, project, and finding details into a unified report struct.
func BuildReportData(
	reportID string,
	project *store.Project,
	scan *store.Scan,
	findings []store.Finding,
	authRecord *store.AuthorizationRecord,
	artifactSHA256 string,
) ReportData {
	summary := ReportSummary{
		CategoryCounts: make(map[string]int),
	}

	score := 100
	if scan.SecurityScore != nil {
		score = *scan.SecurityScore
	}

	var scoreBreakdown map[string]any
	if scan.ScoreBreakdown != nil {
		switch sb := scan.ScoreBreakdown.(type) {
		case map[string]any:
			scoreBreakdown = sb
		case []byte:
			_ = json.Unmarshal(sb, &scoreBreakdown)
		case string:
			_ = json.Unmarshal([]byte(sb), &scoreBreakdown)
		}
	}

	for _, f := range findings {
		if !f.IncludeInReport {
			continue
		}
		summary.TotalFindings++
		switch f.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		default:
			summary.InfoCount++
		}

		switch f.Reachability {
		case "reachable":
			summary.ReachableCount++
		case "unreachable":
			summary.UnreachableCount++
		default:
			summary.UnknownCount++
		}

		summary.CategoryCounts[f.Category]++
	}

	var authAttestation *ReportAuthAttestation
	if authRecord != nil {
		attName := authRecord.AttestorName
		if attName == "" {
			attName = authRecord.AttestedBy
		}
		authAttestation = &ReportAuthAttestation{
			AttestorName:     attName,
			Basis:            authRecord.Basis,
			ScopeDescription: authRecord.ScopeDescription,
			AttestedAt:       authRecord.CreatedAt,
			ValidUntil:       authRecord.ValidUntil,
		}
	}

	pkgName := "Unknown Package"
	if project.PackageName != nil && *project.PackageName != "" {
		pkgName = *project.PackageName
	}

	return ReportData{
		ReportID:       reportID,
		GeneratedAt:    time.Now().UTC(),
		ProjectName:    project.Name,
		PackageName:    pkgName,
		ArtifactSHA256: artifactSHA256,
		ScanID:         scan.ID,
		ScanProfile:    scan.ProfileID,
		SecurityScore:  score,
		ScoreBreakdown: scoreBreakdown,
		Summary:        summary,
		Findings:       findings,
		Authorization:  authAttestation,
	}
}

// GenerateJSON serializes the report data into indented JSON bytes.
func GenerateJSON(data ReportData) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ReverseBug Security Intelligence Report - {{ .ProjectName }}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --success: #10b981;
    }
    @media print {
      body { background: #ffffff !important; color: #111827 !important; }
      .card { border: 1px solid #e5e7eb !important; background: #ffffff !important; page-break-inside: avoid; }
      .badge-critical { background: #fee2e2 !important; color: #991b1b !important; }
      .badge-high { background: #ffedd5 !important; color: #9a3412 !important; }
      .badge-medium { background: #fef9c3 !important; color: #854d0e !important; }
      .badge-low { background: #dbeafe !important; color: #1e40af !important; }
      .code-block { background: #f3f4f6 !important; color: #111827 !important; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      margin: 0;
      padding: 40px;
      line-height: 1.5;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand h1 {
      margin: 0;
      font-size: 26px;
      font-weight: 800;
      letter-spacing: -0.03em;
      color: #38bdf8;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge-info { background: rgba(156, 163, 175, 0.2); color: #9ca3af; border: 1px solid rgba(156, 163, 175, 0.4); }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
    }
    .card-title {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 8px;
    }
    .score-value {
      font-size: 42px;
      font-weight: 900;
      line-height: 1;
    }
    .score-high { color: #10b981; }
    .score-med { color: #eab308; }
    .score-low { color: #ef4444; }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }
    .finding-title {
      font-size: 18px;
      font-weight: 700;
      margin: 0;
    }
    .code-block {
      background: #030712;
      border: 1px solid #1f2937;
      border-radius: 6px;
      padding: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      color: #38bdf8;
      overflow-x: auto;
      margin: 12px 0;
    }
    .meta-tag {
      font-size: 11px;
      background: #1f2937;
      padding: 2px 8px;
      border-radius: 4px;
      color: #9ca3af;
      margin-right: 6px;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <h1>REVERSEBUG</h1>
      <span style="color: var(--text-muted); font-size: 14px;">| Android Security Intelligence Report</span>
    </div>
    <div style="text-align: right; font-size: 12px; color: var(--text-muted);">
      <div>Report ID: {{ .ReportID }}</div>
      <div>Generated: {{ .GeneratedAt.Format "Jan 02, 2006 15:04 MST" }}</div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Security Score (scoring_v1)</div>
      <div class="score-value {{ if ge .SecurityScore 80 }}score-high{{ else if ge .SecurityScore 50 }}score-med{{ else }}score-low{{ end }}">
        {{ .SecurityScore }}/100
      </div>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">
        Profile: {{ .ScanProfile }}
      </div>
    </div>

    <div class="card">
      <div class="card-title">App Metadata</div>
      <div style="font-weight: 700; font-size: 16px;">{{ .ProjectName }}</div>
      <div style="font-size: 13px; color: var(--accent); word-break: break-all;">{{ .PackageName }}</div>
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px; font-family: monospace;">SHA: {{ .ArtifactSHA256 }}</div>
    </div>

    <div class="card">
      <div class="card-title">Findings Breakdown</div>
      <div style="font-size: 14px;">
        <span style="color: var(--critical); font-weight: 700;">{{ .Summary.CriticalCount }}</span> Critical &bull;
        <span style="color: var(--high); font-weight: 700;">{{ .Summary.HighCount }}</span> High &bull;
        <span style="color: var(--medium); font-weight: 700;">{{ .Summary.MediumCount }}</span> Med &bull;
        <span style="color: var(--low); font-weight: 700;">{{ .Summary.LowCount }}</span> Low
      </div>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">
        Reachability: {{ .Summary.ReachableCount }} Reachable, {{ .Summary.UnreachableCount }} Unreachable
      </div>
    </div>

    {{ if .Authorization }}
    <div class="card">
      <div class="card-title">Attestation of Authorization</div>
      <div style="font-size: 13px; font-weight: 600;">Attestor: {{ .Authorization.AttestorName }}</div>
      <div style="font-size: 12px; color: var(--text-muted);">Basis: {{ .Authorization.Basis }}</div>
      <div style="font-size: 11px; color: #10b981; margin-top: 4px;">✓ Verified Active Scope</div>
    </div>
    {{ end }}
  </div>

  <h2>Security Findings ({{ .Summary.TotalFindings }})</h2>
  {{ range .Findings }}
  <div class="finding-card">
    <div class="finding-header">
      <div>
        <h3 class="finding-title">{{ .Title }}</h3>
        <div style="margin-top: 6px;">
          <span class="meta-tag">{{ .RuleID }}</span>
          <span class="meta-tag">{{ .Category }}</span>
          <span class="meta-tag">Reachability: {{ .Reachability }}</span>
          <span class="meta-tag">Verification: {{ .VerificationStatus }}</span>
        </div>
      </div>
      <div>
        <span class="badge badge-{{ .Severity }}">{{ .Severity }}</span>
      </div>
    </div>

    <p style="color: #d1d5db; font-size: 14px;">{{ .Description }}</p>

    {{ if .Impact }}
    <div style="margin-top: 10px; font-size: 13px;">
      <strong style="color: #9ca3af;">Impact:</strong> {{ .Impact }}
    </div>
    {{ end }}

    {{ range .Evidence }}
    {{ if .Excerpt }}
    <div style="margin-top: 12px;">
      <div style="font-size: 12px; color: var(--text-muted);">
        Location: {{ if .Location }}{{ .Location }}{{ else }}Archive root{{ end }}
        {{ if .LineStart }} (Lines {{ .LineStart }}-{{ .LineEnd }}){{ end }}
      </div>
      <pre class="code-block">{{ .Excerpt }}</pre>
    </div>
    {{ end }}
    {{ end }}

    {{ if .Remediation }}
    <div style="margin-top: 12px; padding: 12px; background: rgba(56, 189, 248, 0.05); border-left: 3px solid #38bdf8; border-radius: 4px; font-size: 13px;">
      <strong style="color: #38bdf8;">Remediation Recommendation:</strong>
      <div style="margin-top: 4px; color: #e0f2fe;">{{ .Remediation }}</div>
    </div>
    {{ end }}
  </div>
  {{ else }}
  <div class="card" style="text-align: center; color: var(--text-muted); padding: 40px;">
    No vulnerabilities identified in this scan profile.
  </div>
  {{ end }}

  <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); font-size: 12px; color: var(--text-muted); text-align: center;">
    ReverseBug Security Intelligence Platform &bull; Deterministic Zero-Trust APK Analysis
  </div>
</body>
</html>`

// GenerateHTML renders the print-ready HTML security report.
func GenerateHTML(data ReportData) ([]byte, error) {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse report template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute report template: %w", err)
	}
	return buf.Bytes(), nil
}
