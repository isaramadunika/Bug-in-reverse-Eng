import React, { useEffect, useState } from 'react';
import { apiRequest } from '../../lib/api';
import {
  CreditCard,
  CheckCircle,
  Zap,
  Shield,
  Layers,
  ArrowUpRight,
  Clock,
  AlertCircle,
  FileText,
  Sparkles,
  Check,
  X
} from 'lucide-react';

interface SubscriptionDetail {
  id: string;
  plan_id: string;
  plan_version: number;
  status: string;
  provider: string;
  current_period_start: string;
  current_period_end: string;
  cancel_at_period_end: boolean;
  plan_name: string;
  price_cents: number;
  currency: string;
  interval: string;
  entitlements: Record<string, number | null>;
  usage: Record<string, number>;
}

export const Billing: React.FC = () => {
  const [sub, setSub] = useState<SubscriptionDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [upgradingPlan, setUpgradingPlan] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [actionMsg, setActionMsg] = useState<{ text: string; error?: boolean } | null>(null);

  const fetchSubscription = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await apiRequest<SubscriptionDetail>('/billing/subscription');
      setSub(res);
    } catch (err: any) {
      setError(err.message || 'Failed to load subscription details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSubscription();
  }, []);

  const handleUpgrade = async (planId: string) => {
    if (sub?.plan_id === planId) return;
    try {
      setUpgradingPlan(planId);
      setActionMsg(null);
      const updated = await apiRequest<SubscriptionDetail>('/billing/upgrade', {
        method: 'POST',
        body: JSON.stringify({ plan_id: planId }),
      });
      setSub(updated);
      setActionMsg({ text: `Successfully transitioned to the ${updated.plan_name} plan!` });
    } catch (err: any) {
      setActionMsg({ text: err.message || 'Failed to upgrade plan.', error: true });
    } finally {
      setUpgradingPlan(null);
    }
  };

  const handleCancel = async () => {
    if (!window.confirm('Are you sure you want to cancel your plan renewal? You will retain access until the end of your current billing period.')) {
      return;
    }
    try {
      setCancelling(true);
      setActionMsg(null);
      await apiRequest('/billing/cancel', { method: 'POST' });
      await fetchSubscription();
      setActionMsg({ text: 'Cancellation scheduled. Your plan will remain active until the end of the current period.' });
    } catch (err: any) {
      setActionMsg({ text: err.message || 'Failed to cancel subscription.', error: true });
    } finally {
      setCancelling(false);
    }
  };

  const plans = [
    {
      id: 'free',
      name: 'Free',
      price: '$0',
      period: 'forever',
      description: 'Foundational static security triage for indie researchers and security hobbyists.',
      scans: 5,
      features: [
        '5 automated scans / month',
        'Quick analysis profile (Manifest, DEX, Secrets)',
        'Basic evidence graph visualization',
        'Standard rulepack (OWASP MASVS L1)',
        '14 days retention',
      ],
    },
    {
      id: 'pro',
      name: 'Pro',
      price: '$19',
      period: 'per month',
      description: 'Comprehensive static security intelligence and automated AI agent triage.',
      scans: 50,
      highlight: true,
      features: [
        '50 automated scans / month',
        'Standard profile (Deep rulepacks & data flows)',
        'Full interactive React Flow evidence graph',
        'AI Agent root-cause & triage verification',
        'Interactive Scan Copilot assistant',
        'Print-ready Executive & Developer PDF reports',
        '90 days retention',
      ],
    },
    {
      id: 'researcher',
      name: 'Researcher',
      price: '$49',
      period: 'per month',
      description: 'For dedicated Android red-teamers and independent security consultants.',
      scans: 200,
      features: [
        '200 automated scans / month',
        'Deep profile (Advanced taint & cross-finding correlation)',
        'Unlimited AI reasoning queries',
        'Evidence graph export (PNG, SVG, JSON)',
        'Priority worker queue execution',
        '180 days retention',
      ],
    },
    {
      id: 'team',
      name: 'Team',
      price: '$149',
      period: 'per month',
      description: 'For enterprise security teams and application security testing practices.',
      scans: 1000,
      features: [
        '1,000 automated scans / month',
        'All scan profiles & custom rulepack injection',
        'Unlimited team members & shared workspace',
        'Dedicated worker queue capacity',
        'Custom report branding & white-labeling',
        '365 days retention & compliance logs',
      ],
    },
  ];

  const currentScansUsed = sub?.usage?.scans_this_period || 0;
  const currentScansLimit = sub?.entitlements?.scans_per_month ?? null;
  const usagePercentage = currentScansLimit ? Math.min(100, Math.round((currentScansUsed / currentScansLimit) * 100)) : 0;

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-white/10">
        <div>
          <div className="flex items-center space-x-2">
            <CreditCard className="h-6 w-6 text-brand-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">Subscription & Quotas</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Manage your organization plan tier, view live scan consumption, and configure entitlements.
          </p>
        </div>
      </div>

      {actionMsg && (
        <div
          className={`p-4 rounded-xl text-xs flex items-center space-x-3 ${
            actionMsg.error
              ? 'bg-red-500/10 border border-red-500/20 text-red-300'
              : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-300'
          }`}
        >
          {actionMsg.error ? <AlertCircle className="h-4 w-4 shrink-0" /> : <CheckCircle className="h-4 w-4 shrink-0" />}
          <span>{actionMsg.text}</span>
        </div>
      )}

      {loading ? (
        <div className="p-16 text-center">
          <div className="h-8 w-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-xs text-slate-400">Loading subscription...</p>
        </div>
      ) : error ? (
        <div className="p-6 text-center text-red-400 text-sm bg-navy-900 border border-white/10 rounded-xl">
          {error}
        </div>
      ) : sub ? (
        <>
          {/* Current Plan Overview Card */}
          <div className="bg-gradient-to-br from-navy-900 to-navy-950 border border-white/15 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 w-96 h-96 bg-brand-500/5 rounded-full blur-3xl pointer-events-none" />

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
              {/* Plan info */}
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Current Plan</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    {sub.status}
                  </span>
                </div>
                <h2 className="text-3xl font-extrabold text-white tracking-tight flex items-baseline space-x-2">
                  <span>{sub.plan_name}</span>
                  <span className="text-sm font-normal text-slate-400">
                    ({sub.price_cents === 0 ? 'Free' : `$${(sub.price_cents / 100).toFixed(0)}/mo`})
                  </span>
                </h2>
                <p className="text-xs text-slate-400">
                  {sub.cancel_at_period_end ? (
                    <span className="text-amber-400 font-medium">
                      Cancels at end of period ({new Date(sub.current_period_end).toLocaleDateString()})
                    </span>
                  ) : (
                    <span>
                      Active period ends {new Date(sub.current_period_end).toLocaleDateString()}
                    </span>
                  )}
                </p>
              </div>

              {/* Usage Progress */}
              <div className="bg-navy-950/70 border border-white/10 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium flex items-center space-x-1.5">
                    <Zap className="h-3.5 w-3.5 text-brand-400" />
                    <span>Monthly Scans</span>
                  </span>
                  <span className="font-mono text-cyan-300 font-bold">
                    {currentScansUsed} / {currentScansLimit ?? '∞'}
                  </span>
                </div>
                <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden border border-white/5">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      usagePercentage > 90 ? 'bg-red-500' : usagePercentage > 75 ? 'bg-amber-400' : 'bg-gradient-to-r from-brand-500 to-cyan-400'
                    }`}
                    style={{ width: `${usagePercentage}%` }}
                  />
                </div>
                <div className="text-[11px] text-slate-500 flex justify-between">
                  <span>{usagePercentage}% consumed</span>
                  <span>Resets {new Date(sub.current_period_end).toLocaleDateString()}</span>
                </div>
              </div>

              {/* Actions */}
              <div className="flex flex-col sm:flex-row md:flex-col justify-end space-y-2 text-right">
                {sub.plan_id !== 'free' && !sub.cancel_at_period_end && (
                  <button
                    onClick={handleCancel}
                    disabled={cancelling}
                    className="px-4 py-2 bg-white/5 hover:bg-red-500/10 hover:text-red-300 text-slate-400 rounded-lg text-xs font-medium border border-white/10 transition-colors"
                  >
                    {cancelling ? 'Processing...' : 'Cancel Subscription'}
                  </button>
                )}
                {sub.plan_id === 'free' && (
                  <button
                    onClick={() => handleUpgrade('pro')}
                    className="px-5 py-2.5 bg-gradient-to-r from-brand-600 to-cyan-500 hover:from-brand-500 hover:to-cyan-400 text-white rounded-lg text-xs font-semibold shadow-glow-cyan transition-all"
                  >
                    Upgrade to Pro Tier
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Plan Selector Grid */}
          <div className="space-y-4">
            <h3 className="text-base font-bold text-white tracking-tight">Available Subscription Plans</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {plans.map((p) => {
                const isCurrent = sub.plan_id === p.id;
                const isUpgrading = upgradingPlan === p.id;

                return (
                  <div
                    key={p.id}
                    className={`rounded-2xl p-6 flex flex-col justify-between border transition-all ${
                      isCurrent
                        ? 'bg-navy-900 border-cyan-500/50 shadow-glow-cyan ring-1 ring-cyan-500/30'
                        : p.highlight
                        ? 'bg-navy-900/80 border-brand-500/30 hover:border-brand-500/60'
                        : 'bg-navy-900/40 border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <h4 className="font-bold text-white text-lg">{p.name}</h4>
                        {isCurrent ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                            Active
                          </span>
                        ) : p.highlight ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-brand-500/20 text-brand-300 border border-brand-500/30">
                            Recommended
                          </span>
                        ) : null}
                      </div>

                      <div>
                        <div className="text-2xl font-extrabold text-white">
                          {p.price}
                          <span className="text-xs font-normal text-slate-400 ml-1">/ {p.period}</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1 leading-relaxed min-h-[36px]">
                          {p.description}
                        </p>
                      </div>

                      <div className="pt-4 border-t border-white/10 space-y-2">
                        {p.features.map((feat, idx) => (
                          <div key={idx} className="flex items-start space-x-2 text-xs text-slate-300">
                            <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
                            <span className="leading-snug">{feat}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="pt-6 mt-6 border-t border-white/5">
                      {isCurrent ? (
                        <div className="w-full py-2 bg-white/5 border border-white/10 text-center text-xs font-medium text-slate-400 rounded-lg">
                          Current Plan
                        </div>
                      ) : (
                        <button
                          onClick={() => handleUpgrade(p.id)}
                          disabled={isUpgrading}
                          className={`w-full py-2 text-xs font-semibold rounded-lg transition-all ${
                            p.highlight
                              ? 'bg-gradient-to-r from-brand-600 to-cyan-500 hover:from-brand-500 hover:to-cyan-400 text-white shadow-glow-cyan'
                              : 'bg-white/10 hover:bg-white/15 text-white'
                          } disabled:opacity-50`}
                        >
                          {isUpgrading ? 'Switching...' : `Switch to ${p.name}`}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
};
