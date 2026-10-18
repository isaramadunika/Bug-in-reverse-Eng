import React from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  Terminal, 
  Sparkles, 
  GitBranch, 
  FileText, 
  CheckCircle2, 
  Cpu, 
  Lock, 
  ArrowRight, 
  Search, 
  Layers, 
  ShieldCheck,
  ChevronRight,
  ExternalLink
} from 'lucide-react';

export const Home: React.FC = () => {
  return (
    <div className="space-y-24 py-12">
      {/* Hero Section */}
      <section className="relative px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto text-center space-y-8">
        {/* Glow backdrop */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-gradient-to-tr from-brand-600/20 via-blue-600/10 to-violet-600/10 blur-[100px] -z-10 pointer-events-none rounded-full" />

        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full border border-brand-500/30 bg-brand-500/10 text-brand-300 text-xs font-mono">
          <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
          <span>ReverseBug Security Intelligence Engine v1.0</span>
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-tight">
          Reverse Engineer Smarter.{' '}
          <span className="bg-gradient-to-r from-brand-400 via-cyan-200 to-blue-400 bg-clip-text text-transparent">
            Validate Risks.
          </span>{' '}
          Ship More Secure Android Apps.
        </h1>

        <p className="text-lg sm:text-xl text-slate-300 max-w-2xl mx-auto leading-relaxed">
          Analyze Android APKs with evidence-driven security intelligence, interactive code relationships, AI-assisted investigation, and actionable remediation reports.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
          <Link
            to="/register"
            className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-3.5 text-sm font-semibold text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-lg shadow-glow-cyan transition-all"
          >
            <span>Start Free Analysis</span>
            <ArrowRight className="h-4 w-4 ml-2" />
          </Link>
          <Link
            to="/sample-report"
            className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-3.5 text-sm font-semibold text-slate-200 bg-white/5 hover:bg-white/10 rounded-lg border border-white/10 transition-colors"
          >
            <FileText className="h-4 w-4 mr-2 text-brand-400" />
            <span>Explore Sample Report</span>
          </Link>
        </div>

        {/* Live Interface Preview Mockup */}
        <div className="pt-10 max-w-5xl mx-auto">
          <div className="glass-panel rounded-2xl p-4 sm:p-6 text-left border border-white/10 shadow-glass">
            <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
              <div className="flex items-center space-x-2">
                <div className="h-3 w-3 rounded-full bg-red-500/80" />
                <div className="h-3 w-3 rounded-full bg-yellow-500/80" />
                <div className="h-3 w-3 rounded-full bg-emerald-500/80" />
                <span className="text-xs font-mono text-slate-400 ml-2">
                  sample-target-v2.4.1.apk [SHA256: 9e2b...f81c] — Standard Scan
                </span>
              </div>
              <span className="badge-critical font-mono">Score: 42/100 (High Risk)</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Telemetry Card */}
              <div className="bg-navy-950/80 border border-white/5 rounded-xl p-4 space-y-3">
                <span className="text-[11px] font-mono uppercase text-slate-400">Severity Distribution</span>
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <span className="text-red-400 font-medium">Critical</span>
                    <span className="font-mono text-white">2</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-orange-400 font-medium">High</span>
                    <span className="font-mono text-white">5</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-yellow-400 font-medium">Medium</span>
                    <span className="font-mono text-white">8</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-blue-400 font-medium">Low</span>
                    <span className="font-mono text-white">12</span>
                  </div>
                </div>
              </div>

              {/* Sample Evidence Graph Snippet */}
              <div className="bg-navy-950/80 border border-white/5 rounded-xl p-4 space-y-3">
                <span className="text-[11px] font-mono uppercase text-slate-400">Evidence Graph Relationship</span>
                <div className="font-mono text-[11px] space-y-1 text-slate-300">
                  <div className="p-1.5 rounded bg-brand-500/10 border border-brand-500/20 text-brand-300 truncate">
                    Exported Receiver: AuthSyncReceiver
                  </div>
                  <div className="text-center text-slate-500 text-[10px]">↓ FLOWS_TO (unverified)</div>
                  <div className="p-1.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300 truncate">
                    Method: AccountManager.setAuthToken()
                  </div>
                  <div className="text-center text-slate-500 text-[10px]">↓ WRITES_TO</div>
                  <div className="p-1.5 rounded bg-red-500/10 border border-red-500/20 text-red-300 truncate">
                    Sink: SharedPreferences (MODE_WORLD_READABLE)
                  </div>
                </div>
              </div>

              {/* AI Triage Snippet */}
              <div className="bg-navy-950/80 border border-white/5 rounded-xl p-4 space-y-3">
                <span className="text-[11px] font-mono uppercase text-slate-400">AI Validation Triage</span>
                <div className="text-xs text-slate-300 space-y-2">
                  <div className="flex items-center space-x-1.5 text-brand-400 font-semibold">
                    <ShieldCheck className="h-4 w-4" />
                    <span>Reachability Confirmed</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Agent B confirmed manifest entrypoint lacks <code className="text-cyan-300 font-mono text-[10px]">android:permission</code> restrictions. External intent triggers token overwrite without auth.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Core Workflow (Section 1) */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-12">
        <div className="text-center space-y-3 max-w-3xl mx-auto">
          <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-white">
            From Raw APK to Actionable Remediation
          </h2>
          <p className="text-sm sm:text-base text-slate-400">
            A deterministic, auditable pipeline engineered for software security teams and authorized researchers.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="glass-card rounded-xl p-6 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 font-mono font-bold">
              01
            </div>
            <h3 className="text-base font-semibold text-white">Quarantined Upload</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Upload via browser or secure HTTPS URL. Archives are validated against path traversal, zip bombs, and malformed headers.
            </p>
          </div>

          <div className="glass-card rounded-xl p-6 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 font-mono font-bold">
              02
            </div>
            <h3 className="text-base font-semibold text-white">Static Decompilation</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Automated JADX & Androguard decompilation indexes bytecode, permissions, configurations, components, and secret patterns.
            </p>
          </div>

          <div className="glass-card rounded-xl p-6 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 font-mono font-bold">
              03
            </div>
            <h3 className="text-base font-semibold text-white">Evidence Graph</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Analysis constructs a graph of components, call references, and data-flow sinks. Every finding links to verifiable evidence.
            </p>
          </div>

          <div className="glass-card rounded-xl p-6 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 font-mono font-bold">
              04
            </div>
            <h3 className="text-base font-semibold text-white">AI Remediation Intel</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Narrowly-scoped agents evaluate practical reachability, redact sensitive credentials, calculate risk scores, and export PDF reports.
            </p>
          </div>
        </div>
      </section>

      {/* Security Principles & Trust */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="glass-panel rounded-2xl p-8 sm:p-12 border border-white/10 space-y-8">
          <div className="max-w-2xl space-y-3">
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Honest Security Engineering
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              ReverseBug adheres to strict application security principles: we never claim that every detected weakness is exploitable, and a security score never guarantees an application is bulletproof.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="space-y-2">
              <div className="flex items-center space-x-2 text-brand-400 font-semibold text-sm">
                <CheckCircle2 className="h-4 w-4" />
                <span>Deterministic Scoring</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Scores are calculated using a fixed mathematical function with documented weights. LLMs are used only for explanations.
              </p>
            </div>

            <div className="space-y-2">
              <div className="flex items-center space-x-2 text-brand-400 font-semibold text-sm">
                <CheckCircle2 className="h-4 w-4" />
                <span>Automated Secret Redaction</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Detected credentials, private keys, and tokens are safely redacted before display in the UI, reports, or AI prompts.
              </p>
            </div>

            <div className="space-y-2">
              <div className="flex items-center space-x-2 text-brand-400 font-semibold text-sm">
                <CheckCircle2 className="h-4 w-4" />
                <span>Isolated Worker Workspaces</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Untrusted binaries are analyzed in non-root, ephemeral worker environments with restricted egress and no host access.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Banner */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto text-center space-y-6">
        <h2 className="text-3xl font-bold text-white tracking-tight">
          Ready to inspect your Android security posture?
        </h2>
        <p className="text-slate-400 max-w-xl mx-auto text-sm">
          Get started with our free tier today. Create a project, upload an APK, and inspect evidence-based findings in minutes.
        </p>
        <Link
          to="/register"
          className="inline-flex items-center px-6 py-3 font-semibold text-sm text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-lg shadow-glow-cyan transition-all"
        >
          <span>Create Free Account</span>
          <ArrowRight className="h-4 w-4 ml-2" />
        </Link>
      </section>
    </div>
  );
};
