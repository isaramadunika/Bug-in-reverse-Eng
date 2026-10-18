import React from 'react';
import { 
  BookOpen, 
  Terminal, 
  HelpCircle, 
  ShieldCheck, 
  Code2, 
  Lock, 
  FileCode, 
  Mail,
  AlertTriangle 
} from 'lucide-react';

export const Docs: React.FC = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-16">
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <span className="text-xs font-mono uppercase tracking-widest text-brand-400">Knowledge Base</span>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          ReverseBug Documentation & FAQ
        </h1>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Comprehensive guides for integrating automated APK reverse engineering into your security lifecycle.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {/* Navigation Sidebar */}
        <div className="space-y-4">
          <div className="glass-card rounded-xl p-4 space-y-2 sticky top-24">
            <span className="text-xs font-mono uppercase text-slate-400">Table of Contents</span>
            <ul className="text-xs space-y-2 text-slate-300">
              <li><a href="#quickstart" className="hover:text-brand-400 transition-colors">1. Quickstart Guide</a></li>
              <li><a href="#api" className="hover:text-brand-400 transition-colors">2. REST API & Key Authentication</a></li>
              <li><a href="#profiles" className="hover:text-brand-400 transition-colors">3. Scan Profiles</a></li>
              <li><a href="#faq" className="hover:text-brand-400 transition-colors">4. Frequently Asked Questions</a></li>
              <li><a href="#disclosure" className="hover:text-brand-400 transition-colors">5. Coordinated Disclosure</a></li>
            </ul>
          </div>
        </div>

        {/* Content Body */}
        <div className="md:col-span-2 space-y-12">
          {/* Quickstart */}
          <section id="quickstart" className="glass-card rounded-xl p-6 sm:p-8 space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center space-x-2">
              <BookOpen className="h-5 w-5 text-brand-400" />
              <span>1. Quickstart Guide</span>
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              To scan your first Android application:
            </p>
            <ol className="text-xs text-slate-300 space-y-2 list-decimal list-inside leading-relaxed">
              <li>Register an account and click the verification link sent to your email inbox.</li>
              <li>Navigate to your Dashboard and select <strong>New Project</strong>.</li>
              <li>Provide your application package name and complete the <strong>Attestation of Authorization</strong>.</li>
              <li>Upload your APK file (max 200MB) or provide an HTTPS download URL.</li>
              <li>Select your preferred scan profile and watch real-time analysis progress.</li>
            </ol>
          </section>

          {/* API Reference */}
          <section id="api" className="glass-card rounded-xl p-6 sm:p-8 space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center space-x-2">
              <Terminal className="h-5 w-5 text-brand-400" />
              <span>2. REST API & CI/CD Integration</span>
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Automate scans from GitHub Actions or GitLab CI using your generated API key.
            </p>
            <div className="bg-navy-950 p-4 rounded-lg border border-white/10 font-mono text-xs text-slate-200 overflow-x-auto space-y-2">
              <div className="text-slate-400"># Authenticate with Authorization header</div>
              <code>
                {`curl -X POST https://api.reversebug.local/api/v1/projects/{projectId}/scans \\
  -H "Authorization: Bearer rb_live_a1b2c3d4e5_secret..." \\
  -H "Content-Type: application/json" \\
  -d '{"profile_id": "standard", "artifact_version_id": "..."}'`}
              </code>
            </div>
          </section>

          {/* FAQ */}
          <section id="faq" className="glass-card rounded-xl p-6 sm:p-8 space-y-6">
            <h2 className="text-xl font-bold text-white flex items-center space-x-2">
              <HelpCircle className="h-5 w-5 text-brand-400" />
              <span>3. Frequently Asked Questions (FAQ)</span>
            </h2>

            <div className="space-y-4">
              <div className="border-b border-white/5 pb-4 space-y-1">
                <h4 className="text-sm font-semibold text-white">
                  Does a 100/100 Security Score guarantee our APK cannot be breached?
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  No. A score of 100 indicates the absence of detected risk modeled under our current rule packs and evidence coverage. It does not guarantee that custom zero-day vulnerabilities, server-side backend logic flaws, or hardware attacks do not exist.
                </p>
              </div>

              <div className="border-b border-white/5 pb-4 space-y-1">
                <h4 className="text-sm font-semibold text-white">
                  How does ReverseBug handle sensitive keys discovered during analysis?
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Secrets detected in code are automatically classified, entropy-checked, and safely redacted before presentation in the web interface, generated reports, or LLM reasoning prompts. The raw secret is never used to access third-party services.
                </p>
              </div>

              <div className="border-b border-white/5 pb-4 space-y-1">
                <h4 className="text-sm font-semibold text-white">
                  What are the differences between Quick, Standard, and Deep scans?
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Quick scans inspect manifest declarations, permissions, and top-level configs (&lt;1 min). Standard scans decompile all classes, analyze dependencies, and generate the Evidence Graph (~3-5 mins). Deep scans perform multi-hop inter-procedural data-flow analysis and optional sandbox verification (~10-15 mins).
                </p>
              </div>
            </div>
          </section>

          {/* Disclosure */}
          <section id="disclosure" className="bg-brand-500/10 border border-brand-500/20 rounded-xl p-6 sm:p-8 space-y-3">
            <h3 className="text-base font-bold text-white flex items-center space-x-2">
              <ShieldCheck className="h-5 w-5 text-brand-400" />
              <span>Vulnerability Disclosure & Security Contact</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              If you identify a security weakness within the ReverseBug platform itself, please report it responsibly to{' '}
              <a href="mailto:security@reversebug.local" className="text-brand-300 underline font-mono">
                security@reversebug.local
              </a>. We acknowledge receipt within 24 business hours.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
};
