import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiRequest } from '../../lib/api';
import { CheckCircle2, Sparkles, ArrowRight, ShieldCheck } from 'lucide-react';

interface Plan {
  id: string;
  name: string;
  rank: number;
  price_cents: number;
  currency: string;
  interval: string;
  entitlements: Record<string, number | null>;
}

// Fallback plans if API is booting
const DEFAULT_PLANS: Plan[] = [
  {
    id: 'free',
    name: 'Free',
    rank: 0,
    price_cents: 0,
    currency: 'USD',
    interval: 'month',
    entitlements: {
      scans_per_month: 5,
      'profile.quick': null,
      reports_per_month: 3,
      'evidence_graph.basic': null,
      retention_days: 14,
    },
  },
  {
    id: 'pro',
    name: 'Pro',
    rank: 1,
    price_cents: 1900,
    currency: 'USD',
    interval: 'month',
    entitlements: {
      scans_per_month: 50,
      'profile.quick': null,
      'profile.standard': null,
      'evidence_graph.full': null,
      ai_triage: null,
      version_comparison: null,
      secret_inventory: null,
      reports_per_month: 50,
      retention_days: 90,
    },
  },
  {
    id: 'researcher',
    name: 'Researcher',
    rank: 2,
    price_cents: 4900,
    currency: 'USD',
    interval: 'month',
    entitlements: {
      scans_per_month: 200,
      'profile.quick': null,
      'profile.standard': null,
      'profile.deep': null,
      'evidence_graph.full': null,
      ai_triage: null,
      ai_investigation_expanded: null,
      api_access: null,
      reports_per_month: 500,
      retention_days: 365,
    },
  },
  {
    id: 'team',
    name: 'Team',
    rank: 3,
    price_cents: 14900,
    currency: 'USD',
    interval: 'month',
    entitlements: {
      scans_per_month: 1000,
      team_members: 25,
      'profile.quick': null,
      'profile.standard': null,
      'profile.deep': null,
      'evidence_graph.full': null,
      ai_triage: null,
      ai_investigation_expanded: null,
      api_access: null,
      reports_per_month: 2000,
      retention_days: 365,
    },
  },
];

export const Pricing: React.FC = () => {
  const [plans, setPlans] = useState<Plan[]>(DEFAULT_PLANS);

  useEffect(() => {
    apiRequest<{ items: Plan[] }>('/public/plans', { method: 'GET' })
      .then((data) => {
        if (data.items && data.items.length > 0) {
          setPlans(data.items);
        }
      })
      .catch(() => {
        // Fallback already set
      });
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 space-y-20">
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <span className="text-xs font-mono uppercase tracking-widest text-brand-400">Predictable Billing</span>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Flexible Plans for Every Security Team
        </h1>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          From independent bug bounty researchers to enterprise application security teams.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {plans.map((p) => {
          const isPro = p.id === 'pro';
          const isResearcher = p.id === 'researcher';
          return (
            <div
              key={p.id}
              className={`rounded-2xl p-6 sm:p-8 flex flex-col justify-between transition-all ${
                isResearcher
                  ? 'bg-gradient-to-b from-brand-950/60 to-navy-900 border-2 border-brand-500 shadow-glow-cyan relative'
                  : 'glass-card border border-white/10'
              }`}
            >
              {isResearcher && (
                <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-brand-500 text-navy-950 font-bold font-mono text-[10px] uppercase px-3 py-0.5 rounded-full shadow-sm">
                  Most Popular
                </div>
              )}

              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-bold text-white">{p.name}</h3>
                  <div className="mt-4 flex items-baseline text-white">
                    <span className="text-4xl font-extrabold tracking-tight">
                      ${Math.floor(p.price_cents / 100)}
                    </span>
                    <span className="ml-1 text-xs text-slate-400">/month</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    {p.id === 'free' && 'For personal evaluation and open-source Android projects.'}
                    {p.id === 'pro' && 'For security engineers and mobile penetration testers.'}
                    {p.id === 'researcher' && 'Deep analysis profiles, AI triage, and API access.'}
                    {p.id === 'team' && 'Multi-seat collaboration, organization billing, and priority.'}
                  </p>
                </div>

                <div className="pt-4 border-t border-white/10 space-y-3 text-xs text-slate-300">
                  <div className="flex items-center space-x-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                    <span>
                      <strong>{p.entitlements.scans_per_month ?? 'Unlimited'}</strong> Scans / month
                    </span>
                  </div>

                  <div className="flex items-center space-x-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                    <span>
                      {p.id === 'free'
                        ? 'Quick Scan profile'
                        : p.id === 'pro'
                        ? 'Quick & Standard Scans'
                        : 'Quick, Standard & Deep Profiles'}
                    </span>
                  </div>

                  <div className="flex items-center space-x-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                    <span>
                      {p.id === 'free' ? 'Basic Evidence Graph' : 'Full Interactive Evidence Graph'}
                    </span>
                  </div>

                  {p.id !== 'free' && (
                    <div className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                      <span>AI-Assisted Investigation</span>
                    </div>
                  )}

                  {p.id !== 'free' && (
                    <div className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                      <span>Secret & Credential Inventory</span>
                    </div>
                  )}

                  {(p.id === 'researcher' || p.id === 'team') && (
                    <div className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                      <span>REST API Access & Keys</span>
                    </div>
                  )}

                  <div className="flex items-center space-x-2 text-slate-400">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                    <span>{p.entitlements.retention_days ?? 30} Days Artifact Retention</span>
                  </div>
                </div>
              </div>

              <div className="pt-8">
                <Link
                  to="/register"
                  className={`w-full inline-flex items-center justify-center px-4 py-2.5 rounded-lg text-xs font-semibold transition-all ${
                    isResearcher
                      ? 'bg-brand-500 hover:bg-brand-400 text-navy-950 shadow-glow-cyan'
                      : 'bg-white/10 hover:bg-white/20 text-white'
                  }`}
                >
                  <span>{p.id === 'free' ? 'Get Started' : 'Subscribe to ' + p.name}</span>
                  <ArrowRight className="h-3.5 w-3.5 ml-1.5" />
                </Link>
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-navy-950/60 border border-white/5 rounded-xl p-4 text-center text-xs text-slate-400 max-w-2xl mx-auto">
        Notice: Listed rates are launch pricing hypotheses. All limits, feature entitlements, and pricing are fully configurable by system administrators.
      </div>
    </div>
  );
};
