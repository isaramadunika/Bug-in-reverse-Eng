import React from 'react';

export const HowItWorks: React.FC = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-20">
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <span className="text-xs font-mono uppercase tracking-widest text-brand-400">Analysis Lifecycle</span>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          How ReverseBug Evaluates Android Security
        </h1>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          From binary ingestion to standards-mapped remediation, every stage is executed in isolated containers with full evidentiary provenance.
        </p>
      </div>

      <div className="max-w-4xl mx-auto space-y-8">
        {/* Step 1 */}
        <div className="flex items-start space-x-6 glass-card rounded-xl p-6 sm:p-8">
          <div className="h-12 w-12 rounded-xl bg-brand-500/10 border border-brand-500/30 flex items-center justify-center shrink-0 text-brand-400 font-mono font-bold text-lg">
            1
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-white">Quarantine & Artifact Validation</h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              When an APK is uploaded via file picker or imported via an SSRF-hardened HTTPS URL, it is quarantined in private object storage. ReverseBug verifies the central directory, uncompressed ratios, entry counts, and SHA-256 fingerprint before processing.
            </p>
            <div className="pt-2 text-xs text-brand-400 font-mono">
              Defenses: Zip-bomb limit (200MB), Path traversal defense, MIME-spoofing rejection.
            </div>
          </div>
        </div>

        {/* Step 2 */}
        <div className="flex items-start space-x-6 glass-card rounded-xl p-6 sm:p-8">
          <div className="h-12 w-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0 text-cyan-400 font-mono font-bold text-lg">
            2
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-white">Attestation of Authorization & Scan Profile Selection</h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              To adhere to ethical security research standards, an Attestation of Authorization must be recorded for the target project. You then choose between Quick Scan, Standard Scan, or Deep Analysis based on required coverage.
            </p>
            <div className="pt-2 text-xs text-cyan-400 font-mono">
              Profiles: Quick (manifest/permissions), Standard (decompilation/secrets), Deep (call graphs/dataflow).
            </div>
          </div>
        </div>

        {/* Step 3 */}
        <div className="flex items-start space-x-6 glass-card rounded-xl p-6 sm:p-8">
          <div className="h-12 w-12 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center shrink-0 text-blue-400 font-mono font-bold text-lg">
            3
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-white">Decompilation, Rule Packs & Secret Scanning</h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Worker processes decompile the DEX bytecode and extract the parsed manifest. Configured rule packs analyze exported components, trust managers, cryptographic usages, WebViews, and unsafe deep links. Entropy detectors identify embedded credentials.
            </p>
            <div className="pt-2 text-xs text-blue-400 font-mono">
              Engines: JADX, Androguard, Shannon entropy, CycloneDX SBOM generator.
            </div>
          </div>
        </div>

        {/* Step 4 */}
        <div className="flex items-start space-x-6 glass-card rounded-xl p-6 sm:p-8">
          <div className="h-12 w-12 rounded-xl bg-violet-500/10 border border-violet-500/30 flex items-center justify-center shrink-0 text-violet-400 font-mono font-bold text-lg">
            4
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-white">Evidence Graph Construction & Reachability Analysis</h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              The engine builds an interactive Evidence Graph linking manifest entry points to internal method invocations and sensitive sinks. AI Agent B (Validation Analyst) tests whether entry conditions and permissions allow practical reachability.
            </p>
            <div className="pt-2 text-xs text-violet-400 font-mono">
              Status tags: Static Evidence, Runtime Validated, Likely False Positive, Inconclusive.
            </div>
          </div>
        </div>

        {/* Step 5 */}
        <div className="flex items-start space-x-6 glass-card rounded-xl p-6 sm:p-8">
          <div className="h-12 w-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0 text-emerald-400 font-mono font-bold text-lg">
            5
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-white">Deterministic Scoring & Remediation Reports</h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              A pure versioned scoring algorithm calculates the ReverseBug Security Score (0-100). PDF, JSON, and CSV reports are generated containing verified evidence references, OWASP MASVS mappings, and prioritized defensive patches.
            </p>
            <div className="pt-2 text-xs text-emerald-400 font-mono">
              Outputs: Executive PDF Report, Machine-readable JSON, Regression test recommendations.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
