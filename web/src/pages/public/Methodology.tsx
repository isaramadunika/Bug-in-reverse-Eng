import React from 'react';
import { ShieldAlert, BookOpen, AlertCircle, CheckCircle2, Scale, Percent } from 'lucide-react';

export const Methodology: React.FC = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-20">
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <span className="text-xs font-mono uppercase tracking-widest text-brand-400">Scientific Foundation</span>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Security Methodology & Scoring Engine
        </h1>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Transparent, deterministic, and evidence-based. We prioritize verifiable security findings over speculative claims.
        </p>
      </div>

      {/* Scoring Engine Breakdown */}
      <section className="glass-panel rounded-2xl p-8 sm:p-12 border border-white/10 space-y-8">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-2xl font-bold text-white tracking-tight">The ReverseBug Security Score (0 - 100)</h2>
            <p className="text-xs font-mono text-brand-400 mt-1">Version: scoring_v1.0 (Deterministic Algorithm)</p>
          </div>
          <div className="bg-brand-500/10 border border-brand-500/20 px-3 py-1.5 rounded-lg text-xs font-mono text-brand-300">
            100 = Lower Detected Risk | 0 = Highest Detected Risk
          </div>
        </div>

        <p className="text-sm text-slate-300 leading-relaxed max-w-4xl">
          The ReverseBug Security Score represents the absence of detected risk modeled across verified findings. 
          Unlike generative AI score inventions, our score is computed via a pure function using normalized penalty factors and duplicate suppression.
        </p>

        {/* Weights Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 pt-4">
          <div className="bg-navy-950/80 border border-white/5 rounded-xl p-4 space-y-2">
            <span className="text-2xl font-mono font-bold text-red-400">30%</span>
            <h4 className="text-xs font-semibold text-white">Vulnerability Severity</h4>
            <p className="text-[11px] text-slate-400 leading-normal">
              Weighted aggregate of Critical (1.0), High (0.6), Medium (0.3), and Low (0.1) confirmed findings.
            </p>
          </div>

          <div className="bg-navy-950/80 border border-white/5 rounded-xl p-4 space-y-2">
            <span className="text-2xl font-mono font-bold text-cyan-400">20%</span>
            <h4 className="text-xs font-semibold text-white">Evidence Confidence</h4>
            <p className="text-[11px] text-slate-400 leading-normal">
              Penalties scaled by direct observation confidence: High (1.0), Medium (0.7), and Low (0.4).
            </p>
          </div>

          <div className="bg-navy-950/80 border border-white/5 rounded-xl p-4 space-y-2">
            <span className="text-2xl font-mono font-bold text-amber-400">20%</span>
            <h4 className="text-xs font-semibold text-white">Reachability & Exposure</h4>
            <p className="text-[11px] text-slate-400 leading-normal">
              Reachability from exported components or unsanitized deep-links without permission checks.
            </p>
          </div>

          <div className="bg-navy-950/80 border border-white/5 rounded-xl p-4 space-y-2">
            <span className="text-2xl font-mono font-bold text-blue-400">15%</span>
            <h4 className="text-xs font-semibold text-white">Sensitive-Data Exposure</h4>
            <p className="text-[11px] text-slate-400 leading-normal">
              Verified private keys, cloud access secrets, and world-readable SharedPreferences.
            </p>
          </div>

          <div className="bg-navy-950/80 border border-white/5 rounded-xl p-4 space-y-2">
            <span className="text-2xl font-mono font-bold text-violet-400">15%</span>
            <h4 className="text-xs font-semibold text-white">Config & Dependencies</h4>
            <p className="text-[11px] text-slate-400 leading-normal">
              Insecure network security configurations, debuggable flags, and known CVE dependencies.
            </p>
          </div>
        </div>
      </section>

      {/* Verification Statuses */}
      <section className="space-y-6">
        <h3 className="text-xl font-bold text-white tracking-tight">Finding Verification Status Taxonomy</h3>
        <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">
          Every weakness reported by ReverseBug is assigned one of five explicit verification states:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="glass-card rounded-xl p-5 space-y-2">
            <span className="badge-critical font-mono">static_evidence</span>
            <h4 className="text-sm font-semibold text-white pt-2">Static Evidence</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Weakness observed directly in decompiled code or manifest XML, but not yet dynamically exercised in a sandbox.
            </p>
          </div>

          <div className="glass-card rounded-xl p-5 space-y-2">
            <span className="badge-high font-mono">runtime_validated</span>
            <h4 className="text-sm font-semibold text-white pt-2">Runtime Validated</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Demonstrated through non-destructive invocation inside an isolated Android emulator with synthetic test inputs.
            </p>
          </div>

          <div className="glass-card rounded-xl p-5 space-y-2">
            <span className="badge-info font-mono">likely_false_positive</span>
            <h4 className="text-sm font-semibold text-white pt-2">Likely False Positive</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Static pattern was detected, but context checks (such as test fixtures, dead code, or runtime guards) mitigate risk.
            </p>
          </div>

          <div className="glass-card rounded-xl p-5 space-y-2">
            <span className="badge-medium font-mono">inconclusive</span>
            <h4 className="text-sm font-semibold text-white pt-2">Inconclusive</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Code structure is obfuscated (e.g., DexGuard, reflection) and cannot be proven reachable without manual analysis.
            </p>
          </div>

          <div className="glass-card rounded-xl p-5 space-y-2">
            <span className="badge-low font-mono">needs_human_review</span>
            <h4 className="text-sm font-semibold text-white pt-2">Needs Human Review</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              High-impact finding with ambiguous business context flagged for manual review by an authorized security specialist.
            </p>
          </div>
        </div>
      </section>

      {/* Non-Exploitation Disclaimer */}
      <section className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 space-y-3">
        <div className="flex items-center space-x-2 text-red-400 font-bold text-sm">
          <AlertCircle className="h-5 w-5" />
          <span>Non-Exploitation & Safety Boundaries</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          ReverseBug never attempts unauthorized access against external servers, never leverages discovered credentials to access live user accounts, and never attacks unrelated third-party applications. All reachability checks prioritize non-destructive static graph analysis and isolated ephemeral sandboxes.
        </p>
      </section>
    </div>
  );
};
