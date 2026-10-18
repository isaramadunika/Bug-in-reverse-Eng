import React from 'react';
import { Link } from 'react-router-dom';
import { 
  FileText, 
  ShieldAlert, 
  Download, 
  GitBranch, 
  CheckCircle2, 
  AlertTriangle, 
  Lock, 
  Code2, 
  ExternalLink,
  Info
} from 'lucide-react';

export const SampleReport: React.FC = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-12">
      {/* Banner */}
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-center justify-between text-xs text-amber-300">
        <div className="flex items-center space-x-2">
          <Info className="h-4 w-4 shrink-0 text-amber-400" />
          <span>
            <strong>DEMO / SAMPLE ARTIFACT:</strong> This report is rendered using verified benchmark sample data to demonstrate report formatting, evidence linkage, and OWASP mappings.
          </span>
        </div>
        <Link to="/register" className="font-semibold underline hover:text-white shrink-0 ml-4">
          Scan Your APK
        </Link>
      </div>

      {/* Report Header Card */}
      <div className="glass-panel rounded-2xl p-6 sm:p-10 border border-white/10 space-y-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-6">
          <div>
            <div className="inline-flex items-center space-x-2 text-xs font-mono text-brand-400 mb-1">
              <span>REPORT-ID: RB-2026-DEMO-0042</span>
              <span>•</span>
              <span>GENERATED: 2026-10-18 UTC</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white">
              Android Application Security Assessment
            </h1>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Target: com.example.financial.wallet v2.4.0 (VersionCode: 240)
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <div className="text-right">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Security Score</span>
              <span className="text-3xl font-bold font-mono text-red-400">46 / 100</span>
              <span className="text-[10px] font-mono text-red-300 block">HIGH RISK</span>
            </div>
          </div>
        </div>

        {/* Artifact Metadata */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
          <div className="bg-navy-950/60 p-3 rounded-lg border border-white/5 space-y-1">
            <span className="text-slate-400 text-[10px] uppercase font-mono">SHA-256 Hash</span>
            <p className="font-mono text-slate-200 truncate" title="7f3b890a2c4e5d6f1a8b9c0d2e4f6a8b1c3d5e7f9a0b2c4e6f8a1b3d5e7f9a0b">
              7f3b890a2c4e5d...
            </p>
          </div>
          <div className="bg-navy-950/60 p-3 rounded-lg border border-white/5 space-y-1">
            <span className="text-slate-400 text-[10px] uppercase font-mono">Min / Target SDK</span>
            <p className="font-mono text-slate-200">API 26 / API 34</p>
          </div>
          <div className="bg-navy-950/60 p-3 rounded-lg border border-white/5 space-y-1">
            <span className="text-slate-400 text-[10px] uppercase font-mono">Analysis Profile</span>
            <p className="font-mono text-slate-200">Standard Profile v1</p>
          </div>
          <div className="bg-navy-950/60 p-3 rounded-lg border border-white/5 space-y-1">
            <span className="text-slate-400 text-[10px] uppercase font-mono">Authorization Basis</span>
            <p className="font-mono text-slate-200">Internal Security Audit</p>
          </div>
        </div>

        {/* Severity Summary */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
            Executive Summary & Severity Distribution
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-center">
              <span className="text-xl font-bold font-mono text-red-400">1</span>
              <span className="block text-[11px] text-red-300 font-medium">Critical</span>
            </div>
            <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/20 text-center">
              <span className="text-xl font-bold font-mono text-orange-400">2</span>
              <span className="block text-[11px] text-orange-300 font-medium">High</span>
            </div>
            <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-center">
              <span className="text-xl font-bold font-mono text-yellow-400">3</span>
              <span className="block text-[11px] text-yellow-300 font-medium">Medium</span>
            </div>
            <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-center">
              <span className="text-xl font-bold font-mono text-blue-400">5</span>
              <span className="block text-[11px] text-blue-300 font-medium">Low</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-500/10 border border-slate-500/20 text-center col-span-2 sm:col-span-1">
              <span className="text-xl font-bold font-mono text-slate-300">4</span>
              <span className="block text-[11px] text-slate-400 font-medium">Info</span>
            </div>
          </div>
        </div>

        {/* Prioritized Findings List */}
        <div className="space-y-6 pt-6 border-t border-white/10">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
            Detailed Prioritized Findings
          </h3>

          {/* Finding 1 */}
          <div className="glass-card rounded-xl p-6 space-y-4 border-l-4 border-l-red-500">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center space-x-2">
                <span className="badge-critical font-mono">CRITICAL</span>
                <h4 className="text-base font-bold text-white">
                  Hardcoded Cloud Secret Access Key in Decompiled Class
                </h4>
              </div>
              <span className="text-xs font-mono text-slate-400">CWE-798 | MASVS-CRYPTO-1</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Automated entropy analysis detected an active AWS access credential embedded directly in decompiled Java bytecode. The key possesses permissions to read financial transaction records stored in S3 buckets.
            </p>

            {/* Sanitized Evidence Box */}
            <div className="bg-navy-950 p-4 rounded-lg border border-white/10 space-y-2">
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Location: com/example/financial/sync/CloudSyncClient.java:L48</span>
                <span className="text-emerald-400">Verification: Static Evidence (Confidence: High)</span>
              </div>
              <pre className="font-mono text-xs text-slate-200 overflow-x-auto p-2 bg-black/40 rounded">
                <code>
                  {`// Redacted Evidence (Original preserved in restricted storage)
public class CloudSyncClient {
    private static final String AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY[REDACTED_SECRET]";
}`}
                </code>
              </pre>
            </div>

            <div className="pt-2 text-xs text-slate-300">
              <strong className="text-white">Remediation:</strong> Immediately revoke this key in the AWS IAM Console. Migrate authentication to short-lived AWS STS assume-role credentials delivered via an authenticated backend session.
            </div>
          </div>

          {/* Finding 2 */}
          <div className="glass-card rounded-xl p-6 space-y-4 border-l-4 border-l-orange-500">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center space-x-2">
                <span className="badge-high font-mono">HIGH</span>
                <h4 className="text-base font-bold text-white">
                  Exported BroadcastReceiver Without Signature Permission
                </h4>
              </div>
              <span className="text-xs font-mono text-slate-400">CWE-926 | MASVS-PLATFORM-1</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              The component <code className="text-cyan-300 font-mono">com.example.financial.AuthSyncReceiver</code> is marked <code className="text-cyan-300 font-mono">exported="true"</code> without requiring permission restrictions. Malicious third-party apps installed on the same device can broadcast spoofed intents to trigger account balance resets.
            </p>

            <div className="bg-navy-950 p-4 rounded-lg border border-white/10 space-y-2">
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Location: AndroidManifest.xml:L84</span>
                <span className="text-orange-400">Status: Reachable from Entrypoint</span>
              </div>
              <pre className="font-mono text-xs text-slate-200 overflow-x-auto p-2 bg-black/40 rounded">
                <code>
                  {`<receiver android:name=".AuthSyncReceiver" android:exported="true">
    <intent-filter>
        <action android:name="com.example.financial.ACTION_FORCE_SYNC" />
    </intent-filter>
</receiver>`}
                </code>
              </pre>
            </div>

            <div className="pt-2 text-xs text-slate-300">
              <strong className="text-white">Remediation:</strong> Set <code className="text-cyan-300 font-mono">android:exported="false"</code> if the receiver is intended only for internal use, or protect it with a custom <code className="text-cyan-300 font-mono">signature</code> protectionLevel permission.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
