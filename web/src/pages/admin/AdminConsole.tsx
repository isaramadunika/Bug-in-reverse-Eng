import React, { useEffect, useState } from 'react';
import { apiRequest } from '../../lib/api';
import { useAuth } from '../../context/AuthContext';
import {
  ShieldAlert,
  Users,
  Database,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Unlock,
  Search,
  RefreshCw,
  Clock,
  Sparkles,
  Layers,
  FileCode,
  ShieldCheck,
  ChevronDown,
  ChevronRight
} from 'lucide-react';

interface PlatformStats {
  total_users: number;
  active_users: number;
  total_projects: number;
  total_scans: number;
  completed_scans: number;
  average_score: number;
  total_findings: number;
  total_storage_bytes: number;
  total_agent_runs: number;
}

interface AdminUser {
  id: string;
  email: string;
  display_name: string;
  platform_role: string;
  status: string;
  email_verified_at?: string;
  mfa_enabled_at?: string;
  failed_login_count: number;
  locked_until?: string;
  last_login_at?: string;
  created_at: string;
  project_count: number;
  scan_count: number;
}

interface AuditEvent {
  id: number;
  occurred_at: string;
  actor_user_id?: string;
  actor_type: string;
  action: string;
  target_type?: string;
  target_id?: string;
  outcome: string;
  ip_address?: string;
  metadata: any;
  prev_hash_hex: string;
  row_hash_hex: string;
}

export const AdminConsole: React.FC = () => {
  const { user } = useAuth();

  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'audit'>('overview');
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(false);

  // Audit verify state
  const [verifyState, setVerifyState] = useState<{
    checked?: number;
    intact?: boolean;
    broken_id?: number;
    loading?: boolean;
  } | null>(null);

  // Users state
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [usersTotal, setUsersTotal] = useState(0);
  const [usersLoading, setUsersLoading] = useState(false);
  const [userSearch, setUserSearch] = useState('');
  const [userStatusFilter, setUserStatusFilter] = useState('all');
  const [userRoleFilter, setUserRoleFilter] = useState('all');

  // User management action modal
  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null);
  const [actionStatus, setActionStatus] = useState<'active' | 'suspended' | 'locked'>('active');
  const [lockMinutes, setLockMinutes] = useState('60');
  const [updatingUser, setUpdatingUser] = useState(false);

  // Audit events state
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);

  const fetchStats = async () => {
    try {
      setStatsLoading(true);
      const res = await apiRequest<PlatformStats>('/admin/stats');
      setStats(res);
    } catch (err) {
      console.error(err);
    } finally {
      setStatsLoading(false);
    }
  };

  const verifyAuditChain = async () => {
    try {
      setVerifyState({ loading: true });
      const res = await apiRequest<{ checked: number; intact: boolean; first_broken_id: number }>('/admin/audit/verify');
      setVerifyState({
        checked: res.checked,
        intact: res.intact,
        broken_id: res.first_broken_id,
        loading: false,
      });
    } catch (err: any) {
      alert(err.message || 'Audit verification failed.');
      setVerifyState(null);
    }
  };

  const fetchUsers = async () => {
    try {
      setUsersLoading(true);
      const params = new URLSearchParams();
      if (userSearch) params.set('search', userSearch);
      if (userStatusFilter !== 'all') params.set('status', userStatusFilter);
      if (userRoleFilter !== 'all') params.set('platform_role', userRoleFilter);
      params.set('limit', '50');

      const res = await apiRequest<{ items: AdminUser[]; total: number }>(`/admin/users?${params.toString()}`);
      setUsers(res.items || []);
      setUsersTotal(res.total || 0);
    } catch (err) {
      console.error(err);
    } finally {
      setUsersLoading(false);
    }
  };

  const fetchAuditEvents = async () => {
    try {
      setAuditLoading(true);
      const res = await apiRequest<{ items: AuditEvent[] }>('/admin/audit/events?limit=50');
      setAuditEvents(res.items || []);
    } catch (err) {
      console.error(err);
    } finally {
      setAuditLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    verifyAuditChain();
  }, []);

  useEffect(() => {
    if (activeTab === 'users') {
      fetchUsers();
    } else if (activeTab === 'audit') {
      fetchAuditEvents();
    }
  }, [activeTab]);

  const handleUpdateUserStatus = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;
    try {
      setUpdatingUser(true);
      await apiRequest(`/admin/users/${selectedUser.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: actionStatus,
          locked_minutes: actionStatus === 'locked' ? parseInt(lockMinutes, 10) : undefined,
        }),
      });
      setSelectedUser(null);
      await fetchUsers();
    } catch (err: any) {
      alert(err.message || 'Failed to update user status.');
    } finally {
      setUpdatingUser(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-white/10">
        <div>
          <div className="flex items-center space-x-2">
            <ShieldAlert className="h-6 w-6 text-brand-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">Administrator Console</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-brand-500/20 text-brand-300 border border-brand-500/30">
              {user?.platform_role}
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Authoritative platform telemetry, user account controls, and cryptographic audit log chain verification.
          </p>
        </div>

        {/* Audit Chain Verifier CTA */}
        <div className="flex items-center space-x-3">
          <button
            onClick={verifyAuditChain}
            disabled={verifyState?.loading}
            className="inline-flex items-center space-x-2 px-3.5 py-2 bg-navy-900 hover:bg-navy-800 border border-brand-500/40 text-brand-300 rounded-lg text-xs font-semibold shadow-glow-cyan transition-all disabled:opacity-50"
          >
            <ShieldCheck className={`h-4 w-4 ${verifyState?.loading ? 'animate-spin' : 'text-cyan-400'}`} />
            <span>Verify Hash Chain</span>
          </button>
        </div>
      </div>

      {/* Hash Chain Integrity Status Banner */}
      {verifyState && !verifyState.loading && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between text-xs ${
            verifyState.intact
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-red-500/10 border-red-500/30 text-red-300'
          }`}
        >
          <div className="flex items-center space-x-3">
            {verifyState.intact ? (
              <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="h-5 w-5 text-red-400 shrink-0" />
            )}
            <div>
              <p className="font-semibold text-white">
                {verifyState.intact
                  ? 'Cryptographic Audit Log Intact'
                  : `Audit Chain Tamper Warning at ID #${verifyState.broken_id}`}
              </p>
              <p className="text-slate-400 mt-0.5">
                {verifyState.intact
                  ? `All ${verifyState.checked?.toLocaleString()} audit log events sequentially linked via SHA256 HMAC hash chain.`
                  : 'A discrepancy was detected in the hash chain sequence. Verify database audit_events table immediately.'}
              </p>
            </div>
          </div>
          <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-black/30 border border-white/10">
            {verifyState.intact ? 'Tamper Evident' : 'Tamper Detected'}
          </span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-white/10 space-x-6 text-sm">
        {[
          { id: 'overview', label: 'Platform Overview', icon: Activity },
          { id: 'users', label: 'User Management', icon: Users },
          { id: 'audit', label: 'Hash-Chain Audit Trail', icon: Database },
        ].map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 pb-3 font-medium text-xs tracking-wider uppercase transition-colors relative ${
                active ? 'text-brand-400' : 'text-slate-400 hover:text-white'
              }`}
            >
              <Icon className="h-4 w-4" />
              <span>{tab.label}</span>
              {active && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-brand-400" />}
            </button>
          );
        })}
      </div>

      {/* Tab: Platform Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                title: 'Total Users',
                value: stats?.total_users ?? 0,
                sub: `${stats?.active_users ?? 0} active accounts`,
                icon: Users,
                color: 'text-brand-400',
              },
              {
                title: 'Total Projects',
                value: stats?.total_projects ?? 0,
                sub: 'Registered mobile workspaces',
                icon: Layers,
                color: 'text-cyan-400',
              },
              {
                title: 'Scans Executed',
                value: stats?.total_scans ?? 0,
                sub: `${stats?.completed_scans ?? 0} completed`,
                icon: Activity,
                color: 'text-blue-400',
              },
              {
                title: 'Avg Security Score',
                value: stats ? stats.average_score.toFixed(1) : '100.0',
                sub: 'Out of 100 possible points',
                icon: ShieldCheck,
                color: 'text-emerald-400',
              },
              {
                title: 'Total Findings',
                value: (stats?.total_findings ?? 0).toLocaleString(),
                sub: 'Vulnerabilities & secrets',
                icon: AlertTriangle,
                color: 'text-amber-400',
              },
              {
                title: 'Platform Storage',
                value: formatBytes(stats?.total_storage_bytes ?? 0),
                sub: 'Quarantined APKs & artifacts',
                icon: Database,
                color: 'text-purple-400',
              },
              {
                title: 'AI Agent Runs',
                value: (stats?.total_agent_runs ?? 0).toLocaleString(),
                sub: 'Automated investigations',
                icon: Sparkles,
                color: 'text-cyan-300',
              },
              {
                title: 'Audit Events',
                value: (verifyState?.checked ?? 0).toLocaleString(),
                sub: 'Chained immutable events',
                icon: ShieldAlert,
                color: 'text-slate-300',
              },
            ].map((stat, i) => {
              const Icon = stat.icon;
              return (
                <div key={i} className="bg-navy-900/60 border border-white/10 rounded-xl p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase text-slate-400">{stat.title}</span>
                    <Icon className={`h-4 w-4 ${stat.color}`} />
                  </div>
                  <div className="text-2xl font-extrabold text-white tracking-tight">{stat.value}</div>
                  <div className="text-[11px] text-slate-500">{stat.sub}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab: User Management */}
      {activeTab === 'users' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="bg-navy-900/50 border border-white/10 rounded-xl p-4 flex flex-col sm:flex-row gap-3 items-center justify-between text-xs">
            <div className="relative w-full sm:w-80">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search by email or name..."
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && fetchUsers()}
                className="w-full bg-navy-950 border border-white/10 rounded-lg pl-9 pr-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-xs"
              />
            </div>

            <div className="flex items-center space-x-2 w-full sm:w-auto">
              <select
                value={userStatusFilter}
                onChange={(e) => setUserStatusFilter(e.target.value)}
                className="bg-navy-950 border border-white/10 rounded-lg px-3 py-2 text-slate-300 text-xs focus:outline-none focus:border-brand-500"
              >
                <option value="all">All Statuses</option>
                <option value="active">Active</option>
                <option value="suspended">Suspended</option>
                <option value="locked">Locked</option>
              </select>

              <select
                value={userRoleFilter}
                onChange={(e) => setUserRoleFilter(e.target.value)}
                className="bg-navy-950 border border-white/10 rounded-lg px-3 py-2 text-slate-300 text-xs focus:outline-none focus:border-brand-500"
              >
                <option value="all">All Roles</option>
                <option value="user">User</option>
                <option value="support_admin">Support Admin</option>
                <option value="billing_admin">Billing Admin</option>
                <option value="system_admin">System Admin</option>
              </select>

              <button
                onClick={fetchUsers}
                className="p-2 bg-white/5 hover:bg-white/10 text-slate-300 rounded-lg border border-white/10 transition-colors"
                title="Refresh user list"
              >
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Users Table */}
          <div className="bg-navy-900/50 border border-white/10 rounded-xl overflow-hidden shadow-xl">
            {usersLoading ? (
              <div className="p-12 text-center">
                <div className="h-8 w-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
                <p className="text-xs text-slate-400">Loading user directory...</p>
              </div>
            ) : users.length === 0 ? (
              <div className="p-12 text-center text-slate-400 text-xs">No users matching search criteria.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-navy-950/80 text-slate-400 uppercase font-mono tracking-wider text-[11px] border-b border-white/10">
                    <tr>
                      <th className="py-3 px-6">User</th>
                      <th className="py-3 px-4">Role</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Security</th>
                      <th className="py-3 px-4">Projects / Scans</th>
                      <th className="py-3 px-4">Joined</th>
                      <th className="py-3 px-6 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-slate-300">
                    {users.map((u) => (
                      <tr key={u.id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-4 px-6">
                          <div className="font-semibold text-white">{u.display_name}</div>
                          <div className="text-[11px] text-slate-400 font-mono">{u.email}</div>
                        </td>
                        <td className="py-4 px-4 font-mono">
                          <span className={`px-2 py-0.5 rounded text-[10px] uppercase ${
                            u.platform_role !== 'user' ? 'bg-brand-500/20 text-brand-300 border border-brand-500/30' : 'bg-white/5 text-slate-400'
                          }`}>
                            {u.platform_role.replace('_', ' ')}
                          </span>
                        </td>
                        <td className="py-4 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                            u.status === 'active'
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : u.status === 'suspended'
                              ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                              : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          }`}>
                            {u.status}
                          </span>
                        </td>
                        <td className="py-4 px-4">
                          <div className="space-y-0.5 text-[11px]">
                            <div className={u.email_verified_at ? 'text-emerald-400' : 'text-slate-500'}>
                              {u.email_verified_at ? '✓ Email Verified' : '✕ Unverified'}
                            </div>
                            <div className={u.mfa_enabled_at ? 'text-cyan-400' : 'text-slate-500'}>
                              {u.mfa_enabled_at ? '✓ TOTP MFA' : '✕ No MFA'}
                            </div>
                          </div>
                        </td>
                        <td className="py-4 px-4 font-mono text-slate-200">
                          {u.project_count} proj / {u.scan_count} scans
                        </td>
                        <td className="py-4 px-4 text-slate-400">
                          {new Date(u.created_at).toLocaleDateString()}
                        </td>
                        <td className="py-4 px-6 text-right">
                          <button
                            onClick={() => {
                              setSelectedUser(u);
                              setActionStatus(u.status as any);
                            }}
                            className="px-3 py-1 bg-white/5 hover:bg-white/10 text-slate-300 rounded border border-white/10 transition-colors"
                          >
                            Manage
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: Audit Trail */}
      {activeTab === 'audit' && (
        <div className="bg-navy-900/50 border border-white/10 rounded-xl overflow-hidden shadow-xl space-y-2">
          <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white uppercase font-mono tracking-wider">
              Cryptographic Audit Log Events
            </h3>
            <span className="text-xs text-slate-400">Displaying last 50 events</span>
          </div>

          {auditLoading ? (
            <div className="p-12 text-center">
              <div className="h-8 w-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <p className="text-xs text-slate-400">Loading audit trail...</p>
            </div>
          ) : auditEvents.length === 0 ? (
            <div className="p-12 text-center text-slate-400 text-xs">No audit events recorded.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-950/80 text-slate-400 uppercase font-mono tracking-wider text-[11px] border-b border-white/10">
                  <tr>
                    <th className="py-3 px-4">ID</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Actor</th>
                    <th className="py-3 px-4">Outcome</th>
                    <th className="py-3 px-4">Client IP</th>
                    <th className="py-3 px-6">Row Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-slate-300">
                  {auditEvents.map((ev) => {
                    const isExpanded = expandedEventId === ev.id;
                    return (
                      <React.Fragment key={ev.id}>
                        <tr
                          onClick={() => setExpandedEventId(isExpanded ? null : ev.id)}
                          className="hover:bg-white/[0.02] cursor-pointer transition-colors"
                        >
                          <td className="py-3 px-4 font-mono text-slate-400">#{ev.id}</td>
                          <td className="py-3 px-4 text-slate-400">
                            {new Date(ev.occurred_at).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 font-mono text-cyan-300 font-semibold">{ev.action}</td>
                          <td className="py-3 px-4 font-mono text-slate-400">
                            {ev.actor_type}: {ev.actor_user_id ? ev.actor_user_id.slice(0, 8) + '...' : 'system'}
                          </td>
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                              ev.outcome === 'success'
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : 'bg-red-500/20 text-red-300'
                            }`}>
                              {ev.outcome}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-400">{ev.ip_address || '-'}</td>
                          <td className="py-3 px-6 font-mono text-[10px] text-slate-400 truncate max-w-xs">
                            {ev.row_hash_hex.slice(0, 16)}...
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr className="bg-navy-950/80">
                            <td colSpan={7} className="p-4 space-y-2 border-b border-white/5">
                              <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                                <div>
                                  <span className="text-slate-500">Previous Hash:</span>{' '}
                                  <span className="text-slate-300 select-all">{ev.prev_hash_hex}</span>
                                </div>
                                <div>
                                  <span className="text-slate-500">Row Hash:</span>{' '}
                                  <span className="text-cyan-300 select-all">{ev.row_hash_hex}</span>
                                </div>
                              </div>
                              <div className="mt-2">
                                <span className="text-xs text-slate-400 font-medium">Metadata Payload:</span>
                                <pre className="bg-black/40 p-3 rounded-lg text-emerald-300 text-[11px] overflow-x-auto mt-1 border border-white/5">
                                  {JSON.stringify(ev.metadata, null, 2)}
                                </pre>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Modal: Manage User Status */}
      {selectedUser && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-navy-900 border border-white/15 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl animate-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <h3 className="text-lg font-bold text-white">Manage User Status</h3>
              <button onClick={() => setSelectedUser(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="bg-navy-950 p-3 rounded-lg border border-white/10 text-xs space-y-1">
              <div className="font-semibold text-white">{selectedUser.display_name}</div>
              <div className="text-slate-400 font-mono">{selectedUser.email}</div>
              <div className="text-[11px] text-slate-500">ID: {selectedUser.id}</div>
            </div>

            <form onSubmit={handleUpdateUserStatus} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Account Status</label>
                <select
                  value={actionStatus}
                  onChange={(e) => setActionStatus(e.target.value as any)}
                  className="w-full bg-navy-950 border border-white/10 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-brand-500 text-xs"
                >
                  <option value="active">Active (Permitted to sign in)</option>
                  <option value="suspended">Suspended (All sessions revoked)</option>
                  <option value="locked">Temporary Lockout</option>
                </select>
              </div>

              {actionStatus === 'locked' && (
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Lockout Duration (Minutes)</label>
                  <input
                    type="number"
                    min="1"
                    max="1440"
                    value={lockMinutes}
                    onChange={(e) => setLockMinutes(e.target.value)}
                    className="w-full bg-navy-950 border border-white/10 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-brand-500 text-xs"
                  />
                </div>
              )}

              <div className="pt-3 border-t border-white/10 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setSelectedUser(null)}
                  className="px-4 py-2 bg-white/5 hover:bg-white/10 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={updatingUser}
                  className="px-4 py-2 bg-gradient-to-r from-brand-600 to-cyan-500 hover:from-brand-500 hover:to-cyan-400 text-white font-medium rounded-lg text-xs shadow-glow-cyan disabled:opacity-50"
                >
                  {updatingUser ? 'Updating...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
