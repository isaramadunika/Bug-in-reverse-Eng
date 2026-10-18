import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, Terminal, Lock, CheckCircle2 } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-white/10 bg-navy-950 text-slate-400 text-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-8 mb-12">
          {/* Brand Col */}
          <div className="col-span-2">
            <div className="flex items-center space-x-2.5 mb-3">
              <div className="h-7 w-7 rounded-md bg-brand-600/20 border border-brand-500/30 flex items-center justify-center">
                <ShieldAlert className="h-4 w-4 text-brand-400" />
              </div>
              <span className="font-bold text-base text-slate-100">ReverseBug</span>
            </div>
            <p className="text-slate-400 max-w-sm mb-4 leading-relaxed">
              Evidence-based Android reverse engineering and vulnerability triage. 
              Interactive code relationships, deterministic risk scoring, and actionable remediation intelligence.
            </p>
            <div className="flex items-center space-x-2 text-slate-400 text-[11px] font-mono">
              <span className="inline-block h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>All Systems Operational</span>
              <span>•</span>
              <span>OWASP MASVS Mapped</span>
            </div>
          </div>

          {/* Product Links */}
          <div>
            <h4 className="text-slate-200 font-semibold mb-3">Product</h4>
            <ul className="space-y-2">
              <li><Link to="/features" className="hover:text-white transition-colors">Features</Link></li>
              <li><Link to="/how-it-works" className="hover:text-white transition-colors">How It Works</Link></li>
              <li><Link to="/methodology" className="hover:text-white transition-colors">Security Methodology</Link></li>
              <li><Link to="/sample-report" className="hover:text-white transition-colors">Sample Report</Link></li>
              <li><Link to="/pricing" className="hover:text-white transition-colors">Pricing & Plans</Link></li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="text-slate-200 font-semibold mb-3">Resources</h4>
            <ul className="space-y-2">
              <li><Link to="/docs" className="hover:text-white transition-colors">Documentation</Link></li>
              <li><Link to="/docs#api" className="hover:text-white transition-colors">API Reference</Link></li>
              <li><Link to="/docs#faq" className="hover:text-white transition-colors">FAQ</Link></li>
              <li><Link to="/methodology#scoring" className="hover:text-white transition-colors">Scoring Engine v1</Link></li>
              <li><Link to="/contact" className="hover:text-white transition-colors">Contact Security Team</Link></li>
            </ul>
          </div>

          {/* Governance & Trust */}
          <div>
            <h4 className="text-slate-200 font-semibold mb-3">Trust & Legal</h4>
            <ul className="space-y-2">
              <li><Link to="/privacy" className="hover:text-white transition-colors">Privacy Policy</Link></li>
              <li><Link to="/terms" className="hover:text-white transition-colors">Terms of Service</Link></li>
              <li><Link to="/acceptable-use" className="hover:text-white transition-colors">Acceptable Use Policy</Link></li>
              <li><Link to="/docs#disclosure" className="hover:text-white transition-colors">Vulnerability Disclosure</Link></li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between text-slate-400 text-[11px]">
          <p>© {new Date().getFullYear()} ReverseBug Security Systems. All rights reserved.</p>
          <p className="mt-2 sm:mt-0 font-mono text-[10px]">
            Notice: Detected security weaknesses are evidence-based findings and do not imply unconditional exploitability.
          </p>
        </div>
      </div>
    </footer>
  );
};
