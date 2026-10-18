import React from 'react';
import { 
  ShieldAlert, 
  GitBranch, 
  KeyRound, 
  Bot, 
  FileText, 
  Search, 
  Cpu, 
  Lock, 
  Binary, 
  Layers, 
  CheckCircle2,
  FileCode2,
  ShieldCheck
} from 'lucide-react';

export const Features: React.FC = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-20">
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <span className="text-xs font-mono uppercase tracking-widest text-brand-400">Architecture & Capabilities</span>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Production-Grade Reverse Engineering Features
        </h1>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Engineered for mobile application security engineers, penetration testers, and high-assurance software developers.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        {/* Feature 1 */}
        <div className="glass-card rounded-xl p-6 space-y-4">
          <div className="h-10 w-10 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400">
            <Binary className="h-5 w-5" />
          </div>
          <h3 className="text-lg font-semibold text-white">Full DEX & Resource Decompilation</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Multi-stage extraction using JADX and Androguard parses classes, methods, AndroidManifest.xml, intent-filters, resources, and native ABI libraries into navigable source representations.
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 pt-2">
            <li>• Java & Smali syntax indexing</li>
            <li>• Manifest component permission matrix</li>
            <li>• SDK version & signature verification</li>
          </ul>
        </div>

        {/* Feature 2 */}
        <div className="glass-card rounded-xl p-6 space-y-4">
          <div className="h-10 w-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <GitBranch className="h-5 w-5" />
          </div>
          <h3 className="text-lg font-semibold text-white">Interactive Evidence Graph</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Constructed dynamically using React Flow from actual analysis relationships. Traverses component entrypoints, call sequences, and sensitive sinks without fictional edges.
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 pt-2">
            <li>• Nodes: APK, Components, Methods, Sinks</li>
            <li>• Edges: DECLARES, CALLS, FLOWS_TO</li>
            <li>• Direct jump to Monaco source viewer</li>
          </ul>
        </div>

        {/* Feature 3 */}
        <div className="glass-card rounded-xl p-6 space-y-4">
          <div className="h-10 w-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <KeyRound className="h-5 w-5" />
          </div>
          <h3 className="text-lg font-semibold text-white">Layered Secret & Credential Detection</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Shannon entropy heuristics, pattern classification, and placeholder suppression identify embedded private keys, tokens, and endpoints with automatic redaction.
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 pt-2">
            <li>• Safe redaction in UI, reports, and AI</li>
            <li>• Placeholder & test mock suppression</li>
            <li>• Rotation & remediation guidance</li>
          </ul>
        </div>

        {/* Feature 4 */}
        <div className="glass-card rounded-xl p-6 space-y-4">
          <div className="h-10 w-10 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Bot className="h-5 w-5" />
          </div>
          <h3 className="text-lg font-semibold text-white">Six Narrowly-Scoped AI Agents</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Orchestrated with typed Pydantic contracts and strict token ceilings. Agents inspect reachability, validate entry conditions, and write remediation recommendations.
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 pt-2">
            <li>• Re-analyst & Validation Analyst</li>
            <li>• Risk Assessor & Remediation Advisor</li>
            <li>• Strict prompt-injection defense</li>
          </ul>
        </div>

        {/* Feature 5 */}
        <div className="glass-card rounded-xl p-6 space-y-4">
          <div className="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <h3 className="text-lg font-semibold text-white">Deterministic Scoring Engine v1</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            A versioned mathematical function computes the 0-100 ReverseBug Security Score using verified severity weights, reachability factors, and duplicate finding suppression.
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 pt-2">
            <li>• Fully transparent factor contributions</li>
            <li>• Score delta tracking across versions</li>
            <li>• Explicit insufficient evidence state</li>
          </ul>
        </div>

        {/* Feature 6 */}
        <div className="glass-card rounded-xl p-6 space-y-4">
          <div className="h-10 w-10 rounded-lg bg-violet-500/10 border border-violet-500/30 flex items-center justify-center text-violet-400">
            <FileText className="h-5 w-5" />
          </div>
          <h3 className="text-lg font-semibold text-white">Standardized Security Reports</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Generate executive and technical PDF reports directly from server-side validated database rows, formatted with OWASP MASVS mappings and remediation steps.
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 pt-2">
            <li>• Executive summary & findings breakdown</li>
            <li>• Redacted sensitive inventory</li>
            <li>• JSON and CSV exports for CI/CD</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
