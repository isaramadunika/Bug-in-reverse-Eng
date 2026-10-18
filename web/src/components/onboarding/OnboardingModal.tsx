import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { apiRequest } from '../../lib/api';
import { 
  Sparkles, 
  Layers, 
  FolderPlus, 
  UploadCloud, 
  ShieldCheck, 
  Cpu, 
  Activity, 
  AlertTriangle, 
  GitBranch, 
  Bot, 
  FileDown, 
  KeyRound,
  ChevronRight,
  ChevronLeft,
  X,
  CheckCircle2
} from 'lucide-react';

interface StepContent {
  title: string;
  subtitle: string;
  icon: React.ElementType;
  description: string;
  details: string[];
}

const STEPS: StepContent[] = [
  {
    title: "Welcome to ReverseBug",
    subtitle: "AI-Assisted Android Security Intelligence",
    icon: Sparkles,
    description: "ReverseBug enables security engineers, penetration testers, and mobile developers to inspect Android APK weaknesses, verify supporting evidence, evaluate practical reachability, and generate actionable remediation intelligence.",
    details: [
      "No speculative vulnerability claims: all findings are tied to static code evidence or sandbox logs.",
      "Deterministic 0-100 Security Score based on verified weights, not arbitrary LLM numbers.",
      "Enterprise compliance mappings to OWASP MASVS and CWE."
    ]
  },
  {
    title: "Understanding the Security Dashboard",
    subtitle: "Centralized Telemetry & Risk Aggregation",
    icon: Layers,
    description: "The dashboard aggregates your active scans, vulnerability severity distributions, scan duration benchmarks, and security score trends over time.",
    details: [
      "Real-time pipeline states: Queued, Running, Cancelling, Completed, and Failed.",
      "Severity buckets: Critical, High, Medium, Low, and Info.",
      "Quick actions for starting scans, inspecting API keys, and reading methodology docs."
    ]
  },
  {
    title: "Creating Your First Project",
    subtitle: "Organize Target Applications & Scopes",
    icon: FolderPlus,
    description: "Projects group APK versions for a specific package, preserving revision history, score delta comparisons, and team access permissions.",
    details: [
      "Specify package name, application owner, and deployment environment (staging/prod).",
      "Attach mandatory Attestation of Authorization records before any scan begins.",
      "Team collaboration with role-based member isolation."
    ]
  },
  {
    title: "APK Upload & Direct URL Import",
    subtitle: "Quarantined Binary Ingestion",
    icon: UploadCloud,
    description: "Upload APK binaries directly or import from a verified direct-download HTTPS URL. Uploads are strictly validated against ZIP-bomb and path-traversal attacks before being queued.",
    details: [
      "Cryptographic SHA-256 fingerprinting and signing certificate extraction.",
      "URL import runs through an SSRF-hardened proxy blocking private and cloud-metadata addresses.",
      "Artifacts are quarantined in isolated object storage; binaries never execute on the API server."
    ]
  },
  {
    title: "Attestation of Authorization",
    subtitle: "Ethical & Responsible Security Research",
    icon: ShieldCheck,
    description: "ReverseBug enforces strict authorization attestation. You must record your legal basis before initiating analysis.",
    details: [
      "Supported bases: Application Owner, Employer, Client Contract, or Bug Bounty Scope.",
      "Explicit permission flag required for optional dynamic sandbox verification.",
      "Every authorization record is permanently immutably logged in the audit trail."
    ]
  },
  {
    title: "Selecting an Analysis Profile",
    subtitle: "Quick, Standard, or Deep Analysis",
    icon: Cpu,
    description: "Choose an analysis profile tuned to your assessment needs and compute budget.",
    details: [
      "Quick Scan: Manifest inspection, permission combos, high-confidence static rules (<1 min).",
      "Standard Scan: Full DEX decompilation, secret audit, dependency SBOM, and Evidence Graph.",
      "Deep Analysis: Inter-procedural data-flow tracking, advanced rule packs, and optional sandbox validation."
    ]
  },
  {
    title: "Monitoring Pipeline Progress",
    subtitle: "Transparent Multi-Stage Execution",
    icon: Activity,
    description: "Watch your scan progress through distinct, named pipeline stages with real-time Server-Sent Events (SSE).",
    details: [
      "Stages: validate → hash → manifest → dex → decompile → secrets → rules → normalize → graph → ai_triage → score → report.",
      "Safe failure explanations with stage-level recovery guidance.",
      "Emergency cancellation available at any stage."
    ]
  },
  {
    title: "Findings, Severity & Verification Status",
    subtitle: "Evidence-Backed Vulnerability Triage",
    icon: AlertTriangle,
    description: "Review normalized findings with clear distinction between static suspicion and proven exploitability.",
    details: [
      "Statuses: Static Evidence, Runtime Validated, Likely False Positive, or Inconclusive.",
      "Filter by severity, confidence, CWE, and review status.",
      "Provide reviewer feedback to continuously refine local false-positive detection."
    ]
  },
  {
    title: "The Interactive Evidence Graph",
    subtitle: "Visualizing Code & Data Relationships",
    icon: GitBranch,
    description: "Explore the real React Flow Evidence Graph constructed from static analysis relationships. No fictional or simulated nodes.",
    details: [
      "Node types: Artifacts, Manifest Components, Permissions, Classes, Sinks, and Secrets.",
      "Edge relationships: DECLARES, CALLS, READS_FROM, FLOWS_TO, and VALIDATED_BY.",
      "Click any node to inspect decompiled code excerpts and jump directly to source lines."
    ]
  },
  {
    title: "AI-Assisted Investigation",
    subtitle: "Six Narrowly-Scoped Reasoning Agents",
    icon: Bot,
    description: "Leverage specialized AI agents orchestrated with deterministic schemas and token budgets.",
    details: [
      "Reverse Engineering Analyst: Explains decompiled logic and traces call flows.",
      "Vulnerability Validation Analyst: Checks entrypoint reachability and preconditions.",
      "Sensitive Information Auditor: Classifies discovered credentials with automated redaction."
    ]
  },
  {
    title: "Generating Security Reports",
    subtitle: "Standardized PDF & JSON Exports",
    icon: FileDown,
    description: "Export server-side generated PDF security reports mapped to OWASP MASVS and NIST guidelines.",
    details: [
      "Includes executive summary, score breakdown, prioritized findings, and sanitized evidence excerpts.",
      "Diff reports compare previous versions to highlight newly introduced vs. resolved weaknesses.",
      "JSON and CSV exports available for SIEM and CI/CD pipeline integration."
    ]
  },
  {
    title: "Quotas, Metering & API Keys",
    subtitle: "Seamless Automation & CI/CD Integration",
    icon: KeyRound,
    description: "Integrate ReverseBug into your automated build workflows with scoped, rotatable API keys.",
    details: [
      "Fine-grained scopes: projects:read, scans:create, findings:read, reports:read.",
      "Keys are hashed with pepper at rest and displayed only once upon generation.",
      "Monitor monthly scan allowances and quota usage directly from your settings."
    ]
  }
];

export const OnboardingModal: React.FC = () => {
  const { user, updateUser } = useAuth();
  const [currentStep, setCurrentStep] = useState(user?.onboarding_step || 0);
  const [saving, setSaving] = useState(false);

  // If user has completed onboarding and is not currently on a step, hide modal
  if (!user || !user.show_onboarding) {
    return null;
  }

  const step = STEPS[currentStep] || STEPS[0];
  const StepIcon = step.icon;
  const isLastStep = currentStep === STEPS.length - 1;

  const persistStep = async (nextStep: number, completed: boolean) => {
    setSaving(true);
    try {
      await apiRequest('/me/onboarding', {
        method: 'PUT',
        body: JSON.stringify({ step: nextStep, completed }),
      });
      updateUser({
        onboarding_step: nextStep,
        show_onboarding: !completed,
      });
      setCurrentStep(nextStep);
    } catch (err) {
      console.error('Failed to save onboarding progress:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleNext = () => {
    if (isLastStep) {
      persistStep(currentStep, true);
    } else {
      persistStep(currentStep + 1, false);
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      persistStep(currentStep - 1, false);
    }
  };

  const handleSkip = () => {
    persistStep(currentStep, true);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-2xl bg-navy-900 border border-white/10 rounded-xl shadow-glass overflow-hidden">
        {/* Header Bar */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-navy-950/50">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-medium text-brand-400 bg-brand-500/10 px-2 py-0.5 rounded border border-brand-500/20">
              STEP {currentStep + 1} OF {STEPS.length}
            </span>
            <span className="text-xs text-slate-400">Interactive Product Tour</span>
          </div>
          <button
            onClick={handleSkip}
            className="text-slate-400 hover:text-white p-1 rounded-md transition-colors"
            title="Skip Tour"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-navy-950 h-1">
          <div
            className="bg-gradient-to-r from-brand-500 to-blue-500 h-full transition-all duration-300"
            style={{ width: `${((currentStep + 1) / STEPS.length) * 100}%` }}
          />
        </div>

        {/* Content Body */}
        <div className="p-6 sm:p-8 space-y-6">
          <div className="flex items-start space-x-4">
            <div className="h-12 w-12 rounded-xl bg-brand-500/10 border border-brand-500/30 flex items-center justify-center shrink-0 shadow-glow-cyan">
              <StepIcon className="h-6 w-6 text-brand-400" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white tracking-tight">{step.title}</h3>
              <p className="text-xs font-medium text-brand-400 font-mono mt-0.5">{step.subtitle}</p>
            </div>
          </div>

          <p className="text-sm text-slate-300 leading-relaxed">
            {step.description}
          </p>

          <div className="bg-navy-950/60 border border-white/5 rounded-lg p-4 space-y-2.5">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Key Principles:</span>
            {step.details.map((detail, idx) => (
              <div key={idx} className="flex items-start space-x-2 text-xs text-slate-300">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>{detail}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Controls Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-white/10 bg-navy-950/50">
          <button
            onClick={handleSkip}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            Skip Guide
          </button>

          <div className="flex items-center space-x-3">
            {currentStep > 0 && (
              <button
                onClick={handleBack}
                disabled={saving}
                className="inline-flex items-center px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 rounded-md border border-white/10 transition-colors"
              >
                <ChevronLeft className="h-4 w-4 mr-1" />
                Back
              </button>
            )}

            <button
              onClick={handleNext}
              disabled={saving}
              className="inline-flex items-center px-4 py-1.5 text-xs font-semibold text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-md shadow-glow-cyan transition-all"
            >
              <span>{isLastStep ? 'Finish & Start' : 'Next Step'}</span>
              <ChevronRight className="h-4 w-4 ml-1" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
