import React, { useState } from 'react';
import { Mail, ShieldCheck, CheckCircle2 } from 'lucide-react';

export const Contact: React.FC = () => {
  const [submitted, setSubmitted] = useState(false);

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-12">
      <div className="text-center space-y-4">
        <span className="text-xs font-mono uppercase tracking-widest text-brand-400">Security Communications</span>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Contact ReverseBug Security Team
        </h1>
        <p className="text-slate-400 text-sm leading-relaxed">
          Questions regarding ethical research boundaries, enterprise licenses, or vulnerability reports.
        </p>
      </div>

      <div className="glass-card rounded-2xl p-8 border border-white/10 space-y-6">
        {submitted ? (
          <div className="text-center py-8 space-y-3">
            <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto" />
            <h3 className="text-lg font-bold text-white">Message Dispatched</h3>
            <p className="text-xs text-slate-300">
              Our security team will review your inquiry and respond to your email address within 24 hours.
            </p>
          </div>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setSubmitted(true);
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Your Name</label>
              <input
                type="text"
                required
                className="w-full glass-input px-3.5 py-2 rounded-lg text-sm"
                placeholder="Jane Doe"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Corporate Email</label>
              <input
                type="email"
                required
                className="w-full glass-input px-3.5 py-2 rounded-lg text-sm"
                placeholder="jane@company.com"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Topic</label>
              <select className="w-full glass-input px-3.5 py-2 rounded-lg text-sm bg-navy-900">
                <option value="enterprise">Enterprise Deployment & On-Premises</option>
                <option value="research">Academic or Bug Bounty Research Scope</option>
                <option value="disclosure">Coordinated Vulnerability Disclosure</option>
                <option value="billing">Billing & Custom Invoices</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Inquiry Details</label>
              <textarea
                required
                rows={4}
                className="w-full glass-input px-3.5 py-2 rounded-lg text-sm"
                placeholder="Describe your assessment requirements or question..."
              />
            </div>

            <button
              type="submit"
              className="w-full py-2.5 px-4 font-semibold text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-lg shadow-glow-cyan transition-all"
            >
              Send Secure Message
            </button>
          </form>
        )}
      </div>
    </div>
  );
};
