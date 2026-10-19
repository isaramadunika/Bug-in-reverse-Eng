import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { apiRequest } from '../../lib/api';
import { 
  Layers, 
  Cpu, 
  Activity, 
  AlertTriangle, 
  Plus, 
  Key, 
  BookOpen, 
  FileText, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  TrendingUp, 
  ShieldCheck,
  RefreshCw,
  FolderPlus,
  PlayCircle
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell
} from 'recharts';

interface DashboardData {
  projects: number;
  scans: number;
  running: number;
  queued: number;
  completed: number;
  failed: number;
  findings_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  reports: number;
  scans_per_day: Array<{ day: string; value: number }>;
  avg_scan_duration_seconds: number | null;
  score_trend: Array<{ scan_id: string; project: string; score: number; created_at: string }>;
  recent_scans: Array<{
    id: string;
    project_id: string;
    project_name: string;
    profile: string;
    status: string;
    security_score: number | null;
    created_at: string;
    finished_at: string | null;
    failure_reason: string | null;
  }>;
  recent_activity: Array<{
    action: string;
    target_type: string | null;
    target_id: string | null;
    outcome: string;
    occurred_at: string;
  }>;
  usage_scans_this_period: number;
  quota_scans_per_month: number | null;
  plan_name: string;
  range_days: number;
}

export const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const [data, setData] = useState<DashboardData | null>(null);
  const [days, setDays] = useState(30);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboard = (range: number) => {
    setLoading(true);
    apiRequest<DashboardData>(`/dashboard/summary?days=${range}`, { method: 'GET' })
      .then((res) => {
        setData(res);
        setError(null);
      })
      .catch((err) => {
        setError(err.message || 'Failed to load dashboard metrics.');
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchDashboard(days);
  }, [days]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Top Header & Quick Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <span>Security Operations Dashboard</span>
            <span className="text-xs font-mono font-medium text-brand-400 bg-brand-500/10 px-2 py-0.5 rounded border border-brand-500/20">
              {data?.plan_name || 'Free'} Plan
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time telemetry, vulnerability severity distribution, and scan orchestration.
          </p>
        </div>

        {/* Date Range Selector & Actions */}
        <div className="flex items-center space-x-3">
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="glass-input text-xs px-3 py-1.5 rounded-lg bg-navy-900 border border-white/10 text-slate-300"
          >
            <option value={7}>Last 7 Days</option>
            <option value={30}>Last 30 Days</option>
            <option value={90}>Last 90 Days</option>
          </select>

          <button
            onClick={() => fetchDashboard(days)}
            className="p-1.5 text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 rounded-lg border border-white/10 transition-colors"
            title="Refresh Metrics"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin text-brand-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Quick Action Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Link
          to="/projects?new=1"
          className="glass-card p-4 rounded-xl flex items-center space-x-3 hover:border-brand-500/40 group"
        >
          <div className="h-9 w-9 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 group-hover:scale-105 transition-transform">
            <FolderPlus className="h-4 w-4" />
          </div>
          <div>
            <span className="text-xs font-semibold text-white block">New Project</span>
            <span className="text-[10px] text-slate-400">Add target package</span>
          </div>
        </Link>

        <Link
          to="/scans/new"
          className="glass-card p-4 rounded-xl flex items-center space-x-3 hover:border-brand-500/40 group"
        >
          <div className="h-9 w-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
            <PlayCircle className="h-4 w-4" />
          </div>
          <div>
            <span className="text-xs font-semibold text-white block">Initiate Scan</span>
            <span className="text-[10px] text-slate-400">Upload APK or URL</span>
          </div>
        </Link>

        <Link
          to="/settings#api-keys"
          className="glass-card p-4 rounded-xl flex items-center space-x-3 hover:border-brand-500/40 group"
        >
          <div className="h-9 w-9 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 group-hover:scale-105 transition-transform">
            <Key className="h-4 w-4" />
          </div>
          <div>
            <span className="text-xs font-semibold text-white block">API Keys</span>
            <span className="text-[10px] text-slate-400">CI/CD automation</span>
          </div>
        </Link>

        <Link
          to="/docs"
          className="glass-card p-4 rounded-xl flex items-center space-x-3 hover:border-brand-500/40 group"
        >
          <div className="h-9 w-9 rounded-lg bg-violet-500/10 border border-violet-500/30 flex items-center justify-center text-violet-400 group-hover:scale-105 transition-transform">
            <BookOpen className="h-4 w-4" />
          </div>
          <div>
            <span className="text-xs font-semibold text-white block">Documentation</span>
            <span className="text-[10px] text-slate-400">Rules & guides</span>
          </div>
        </Link>
      </div>

      {/* Main KPI Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="glass-panel p-4 rounded-xl space-y-1">
          <span className="text-[10px] uppercase font-mono text-slate-400">Total Projects</span>
          <p className="text-2xl font-bold font-mono text-white">{data?.projects ?? 0}</p>
          <span className="text-[10px] text-slate-500">Tracked packages</span>
        </div>

        <div className="glass-panel p-4 rounded-xl space-y-1">
          <span className="text-[10px] uppercase font-mono text-slate-400">Total Scans</span>
          <p className="text-2xl font-bold font-mono text-cyan-400">{data?.scans ?? 0}</p>
          <span className="text-[10px] text-slate-500">In period ({days}d)</span>
        </div>

        <div className="glass-panel p-4 rounded-xl space-y-1">
          <span className="text-[10px] uppercase font-mono text-slate-400">Running / Queued</span>
          <div className="flex items-baseline space-x-1.5">
            <span className="text-2xl font-bold font-mono text-brand-400">{data?.running ?? 0}</span>
            <span className="text-xs text-slate-400 font-mono">/ {data?.queued ?? 0}</span>
          </div>
          <span className="text-[10px] text-slate-500">Active workers</span>
        </div>

        <div className="glass-panel p-4 rounded-xl space-y-1">
          <span className="text-[10px] uppercase font-mono text-slate-400">Completed</span>
          <p className="text-2xl font-bold font-mono text-emerald-400">{data?.completed ?? 0}</p>
          <span className="text-[10px] text-slate-500">Ready for review</span>
        </div>

        <div className="glass-panel p-4 rounded-xl space-y-1">
          <span className="text-[10px] uppercase font-mono text-slate-400">Failed Scans</span>
          <p className="text-2xl font-bold font-mono text-red-400">{data?.failed ?? 0}</p>
          <span className="text-[10px] text-slate-500">Errors logged</span>
        </div>

        <div className="glass-panel p-4 rounded-xl space-y-1">
          <span className="text-[10px] uppercase font-mono text-slate-400">Plan Quota</span>
          <div className="flex items-baseline space-x-1 text-xs">
            <span className="font-mono font-bold text-white">{data?.usage_scans_this_period ?? 0}</span>
            <span className="text-slate-400 font-mono">
              / {data?.quota_scans_per_month ? data.quota_scans_per_month : '∞'}
            </span>
          </div>
          <div className="w-full bg-navy-950 h-1 rounded-full mt-2 overflow-hidden">
            <div
              className="bg-brand-500 h-full rounded-full"
              style={{
                width: data?.quota_scans_per_month
                  ? `${Math.min(100, ((data.usage_scans_this_period || 0) / data.quota_scans_per_month) * 100)}%`
                  : '10%',
              }}
            />
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scans Activity Over Time */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
                <TrendingUp className="h-4 w-4 text-brand-400" />
                <span>Scan Volume Trend</span>
              </h3>
              <p className="text-[11px] text-slate-400">Daily executed scans across all authorized projects</p>
            </div>
            {data?.avg_scan_duration_seconds !== null && data?.avg_scan_duration_seconds !== undefined && (
              <div className="text-right">
                <span className="text-[10px] text-slate-500 block uppercase font-mono">Avg Duration</span>
                <span className="font-mono text-xs text-brand-400 font-semibold">
                  {Math.round(data.avg_scan_duration_seconds)}s
                </span>
              </div>
            )}
          </div>

          <div className="h-56 w-full pt-2">
            {data?.scans_per_day && data.scans_per_day.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.scans_per_day}>
                  <defs>
                    <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="day" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={10} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0b1120',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                      fontSize: '11px',
                    }}
                  />
                  <Area type="monotone" dataKey="value" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#scanGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                No scan data recorded in this timeframe
              </div>
            )}
          </div>
        </div>

        {/* Severity Breakdown Bar Chart */}
        <div className="glass-panel p-6 rounded-2xl space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              <span>Findings By Severity</span>
            </h3>
            <p className="text-[11px] text-slate-400">Deduplicated active security weaknesses</p>
          </div>

          <div className="space-y-3 pt-2">
            {[
              { label: 'Critical', count: data?.findings_by_severity.critical ?? 0, color: 'bg-red-500', text: 'text-red-400' },
              { label: 'High', count: data?.findings_by_severity.high ?? 0, color: 'bg-orange-500', text: 'text-orange-400' },
              { label: 'Medium', count: data?.findings_by_severity.medium ?? 0, color: 'bg-yellow-500', text: 'text-yellow-400' },
              { label: 'Low', count: data?.findings_by_severity.low ?? 0, color: 'bg-blue-500', text: 'text-blue-400' },
              { label: 'Info', count: data?.findings_by_severity.info ?? 0, color: 'bg-slate-500', text: 'text-slate-400' },
            ].map((s) => (
              <div key={s.label} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className={`${s.text} font-medium`}>{s.label}</span>
                  <span className="font-mono text-white">{s.count}</span>
                </div>
                <div className="w-full bg-navy-950 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`${s.color} h-full rounded-full transition-all`}
                    style={{
                      width: `${Math.min(
                        100,
                        ((s.count || 0) /
                          Math.max(
                            1,
                            (data?.findings_by_severity.critical || 0) +
                              (data?.findings_by_severity.high || 0) +
                              (data?.findings_by_severity.medium || 0) +
                              (data?.findings_by_severity.low || 0) +
                              (data?.findings_by_severity.info || 0)
                          )) *
                          100
                      )}%`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Recent Security Scans</h3>
            <p className="text-[11px] text-slate-400">Latest analysis jobs submitted in your workspaces</p>
          </div>
          <Link to="/scans" className="text-xs text-brand-400 hover:text-brand-300 font-medium">
            View All Scans
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-white/10 text-slate-400 font-mono text-[11px]">
              <tr>
                <th className="pb-3 font-medium">Project</th>
                <th className="pb-3 font-medium">Profile</th>
                <th className="pb-3 font-medium">Status</th>
                <th className="pb-3 font-medium">Score</th>
                <th className="pb-3 font-medium">Date</th>
                <th className="pb-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              {data?.recent_scans && data.recent_scans.length > 0 ? (
                data.recent_scans.map((s) => (
                  <tr key={s.id} className="hover:bg-white/5 transition-colors">
                    <td className="py-3 font-medium text-white">{s.project_name}</td>
                    <td className="py-3 font-mono capitalize text-slate-400">{s.profile}</td>
                    <td className="py-3">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                          s.status === 'completed'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : s.status === 'running'
                            ? 'bg-brand-500/10 text-brand-400 border border-brand-500/30 animate-pulse'
                            : s.status === 'failed'
                            ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                            : 'bg-slate-500/10 text-slate-400 border border-slate-500/30'
                        }`}
                      >
                        {s.status}
                      </span>
                    </td>
                    <td className="py-3 font-mono">
                      {s.security_score !== null ? (
                        <span
                          className={`font-bold ${
                            s.security_score < 50
                              ? 'text-red-400'
                              : s.security_score < 80
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {s.security_score}/100
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 text-slate-400">
                      {new Date(s.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 text-right">
                      <Link
                        to={`/scans/${s.id}`}
                        className="text-xs text-brand-400 hover:text-white font-medium"
                      >
                        Inspect →
                      </Link>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No scans have been executed yet.{' '}
                    <Link to="/scans/new" className="text-brand-400 underline">
                      Upload an APK to start your first analysis.
                    </Link>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Activity Log */}
      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <h3 className="text-sm font-semibold text-white">Security Audit Trail</h3>
        <p className="text-[11px] text-slate-400">Append-only cryptographic security events for your account</p>

        <div className="space-y-2">
          {data?.recent_activity && data.recent_activity.length > 0 ? (
            data.recent_activity.map((a, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between text-xs py-2 px-3 rounded-lg bg-navy-950/40 border border-white/5 font-mono"
              >
                <div className="flex items-center space-x-2">
                  <span
                    className={`h-2 w-2 rounded-full ${
                      a.outcome === 'success' ? 'bg-emerald-400' : 'bg-red-400'
                    }`}
                  />
                  <span className="text-slate-200">{a.action}</span>
                  {a.target_type && (
                    <span className="text-slate-500">[{a.target_type}]</span>
                  )}
                </div>
                <span className="text-slate-500 text-[10px]">
                  {new Date(a.occurred_at).toLocaleTimeString()}
                </span>
              </div>
            ))
          ) : (
            <div className="text-xs text-slate-500 text-center py-4">No audit events recorded yet.</div>
          )}
        </div>
      </div>
    </div>
  );
};
