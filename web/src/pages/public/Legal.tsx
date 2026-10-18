import React from 'react';

export const Legal: React.FC<{ type: 'privacy' | 'terms' | 'acceptable-use' }> = ({ type }) => {
  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-8 text-slate-300">
      <div className="space-y-2 border-b border-white/10 pb-6">
        <span className="text-xs font-mono uppercase text-brand-400">Legal Agreements</span>
        <h1 className="text-3xl font-extrabold text-white">
          {type === 'privacy' && 'Privacy Policy'}
          {type === 'terms' && 'Terms of Service'}
          {type === 'acceptable-use' && 'Acceptable Use Policy'}
        </h1>
        <p className="text-xs text-slate-400 font-mono">Last Updated: October 2026</p>
      </div>

      {type === 'acceptable-use' && (
        <div className="space-y-6 text-xs sm:text-sm leading-relaxed">
          <h3 className="text-base font-bold text-white">1. Authorized Target Scope</h3>
          <p>
            Users may only submit APK files or direct URLs for applications they personally own, have written contractual permission to evaluate from the copyright owner, or are actively analyzing under an explicit authorized Bug Bounty program scope.
          </p>

          <h3 className="text-base font-bold text-white">2. Prohibited Uses</h3>
          <p>
            You agree not to use ReverseBug to:
          </p>
          <ul className="list-disc list-inside space-y-1 text-slate-400">
            <li>Reverse engineer applications without legal authorization.</li>
            <li>Weaponize findings into active remote exploitation payloads.</li>
            <li>Attempt authentication against production third-party APIs using extracted credentials.</li>
            <li>Exfiltrate end-user personally identifiable information (PII).</li>
            <li>Bypass digital rights management (DRM) for piracy purposes.</li>
          </ul>

          <h3 className="text-base font-bold text-white">3. Violation & Revocation</h3>
          <p>
            Violations of this policy will result in immediate session termination, API key revocation, account suspension, and cooperation with authorized law enforcement when legally mandated.
          </p>
        </div>
      )}

      {type === 'terms' && (
        <div className="space-y-6 text-xs sm:text-sm leading-relaxed">
          <h3 className="text-base font-bold text-white">1. Service Description</h3>
          <p>
            ReverseBug provides automated static analysis, evidence graph modeling, and AI-assisted triage for Android application binaries.
          </p>

          <h3 className="text-base font-bold text-white">2. Disclaimer of Warranties</h3>
          <p>
            THE SERVICE IS PROVIDED "AS IS". REVERSEBUG DOES NOT WARRANT THAT THE SCAN RESULTS WILL DETECT EVERY VULNERABILITY OR GUARANTEE COMPLETE SYSTEM IMMUNITY FROM CYBERATTACKS.
          </p>

          <h3 className="text-base font-bold text-white">3. Subscription & Billing</h3>
          <p>
            Paid subscriptions renew automatically each month until cancelled through account settings. Quotas reset on the first day of each calendar period.
          </p>
        </div>
      )}

      {type === 'privacy' && (
        <div className="space-y-6 text-xs sm:text-sm leading-relaxed">
          <h3 className="text-base font-bold text-white">1. Data Collection & Processing</h3>
          <p>
            We collect account registration data (email, name, password hash), authentication logs, and uploaded application binaries. Uploaded binaries are stored in private, isolated object storage buckets and are processed only to generate your requested security findings.
          </p>

          <h3 className="text-base font-bold text-white">2. Tenant Isolation & Redaction</h3>
          <p>
            Your application artifacts and reports are protected by strict server-enforced tenant boundaries. We never share customer APKs or decompiled code with third parties or public model training sets.
          </p>

          <h3 className="text-base font-bold text-white">3. Right to Erasure</h3>
          <p>
            Users can export their complete account history at any time or submit an automated account deletion request from the Settings page.
          </p>
        </div>
      )}
    </div>
  );
};
