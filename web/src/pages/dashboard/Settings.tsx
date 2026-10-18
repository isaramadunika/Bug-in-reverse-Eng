import React, { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { apiRequest } from '../../lib/api';
import { 
  User, 
  Lock, 
  ShieldCheck, 
  Smartphone, 
  Layers, 
  Download, 
  Trash2, 
  RotateCcw, 
  CheckCircle2, 
  AlertCircle,
  KeyRound,
  LogOut
} from 'lucide-react';

interface SessionItem {
  id: string;
  mfa_verified: boolean;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  current: boolean;
}

export const Settings: React.FC = () => {
  const { user, updateUser, checkSession } = useAuth();

  // Profile Form State
  const [displayName, setDisplayName] = useState(user?.display_name || '');
  const [theme, setTheme] = useState(user?.theme_preference || 'dark');
  const [profileMsg, setProfileMsg] = useState<string | null>(null);

  // Password Form State
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [pwMsg, setPwMsg] = useState<{ text: string; error: boolean } | null>(null);

  // MFA Setup State
  const [mfaSetupData, setMfaSetupData] = useState<{ secret: string; otpauth_url: string } | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [mfaMsg, setMfaMsg] = useState<{ text: string; error: boolean } | null>(null);

  // Sessions State
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [sessionLoading, setSessionLoading] = useState(false);

  // Deletion Dialog State
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteCode, setDeleteCode] = useState('');
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  const loadSessions = () => {
    setSessionLoading(true);
    apiRequest<{ items: SessionItem[] }>('/me/sessions', { method: 'GET' })
      .then((res) => setSessions(res.items || []))
      .catch(() => {})
      .finally(() => setSessionLoading(false));
  };

  useEffect(() => {
    loadSessions();
  }, []);

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfileMsg(null);
    try {
      const updated = await apiRequest<any>('/me', {
        method: 'PATCH',
        body: JSON.stringify({ display_name: displayName, theme_preference: theme }),
      });
      updateUser(updated);
      setProfileMsg('Profile updated successfully.');
    } catch (err: any) {
      setProfileMsg(err.message || 'Failed to update profile.');
    }
  };

  const handleReplayTour = async () => {
    try {
      await apiRequest('/me/onboarding/replay', { method: 'POST' });
      await checkSession();
    } catch (err) {
      console.error(err);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwMsg(null);
    try {
      await apiRequest('/me/password', {
        method: 'POST',
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      setPwMsg({ text: 'Password changed successfully. Other sessions revoked.', error: false });
      setCurrentPassword('');
      setNewPassword('');
      loadSessions();
    } catch (err: any) {
      setPwMsg({ text: err.message || 'Failed to change password.', error: true });
    }
  };

  const handleStartMFASetup = async () => {
    setMfaMsg(null);
    try {
      const data = await apiRequest<{ secret: string; otpauth_url: string }>('/me/mfa/totp/setup', {
        method: 'POST',
      });
      setMfaSetupData(data);
    } catch (err: any) {
      setMfaMsg({ text: err.message || 'Failed to initiate MFA setup.', error: true });
    }
  };

  const handleEnableMFA = async (e: React.FormEvent) => {
    e.preventDefault();
    setMfaMsg(null);
    try {
      await apiRequest('/me/mfa/totp/enable', {
        method: 'POST',
        body: JSON.stringify({ code: mfaCode.trim() }),
      });
      setMfaSetupData(null);
      setMfaCode('');
      setMfaMsg({ text: 'Two-Factor Authentication is now enabled.', error: false });
      updateUser({ mfa_enabled: true });
      loadSessions();
    } catch (err: any) {
      setMfaMsg({ text: err.message || 'Invalid verification code.', error: true });
    }
  };

  const handleRevokeSession = async (sessionID: string) => {
    try {
      await apiRequest(`/me/sessions/${sessionID}`, { method: 'DELETE' });
      loadSessions();
    } catch (err) {
      console.error(err);
    }
  };

  const handleRevokeOtherSessions = async () => {
    try {
      await apiRequest('/me/sessions/revoke-others', { method: 'POST' });
      loadSessions();
    } catch (err) {
      console.error(err);
    }
  };

  const handleExportData = () => {
    window.location.href = '/api/v1/me/export';
  };

  const handleDeleteAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    setDeleteError(null);
    try {
      await apiRequest('/me/deletion', {
        method: 'POST',
        body: JSON.stringify({ password: deletePassword, code: deleteCode }),
      });
      window.location.href = '/login';
    } catch (err: any) {
      setDeleteError(err.message || 'Failed to schedule deletion.');
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-12">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Account & Security Settings</h1>
        <p className="text-xs text-slate-400 mt-1">Manage credentials, multi-factor authentication, active sessions, and data exports</p>
      </div>

      {/* Profile & Product Tour */}
      <div className="glass-panel rounded-2xl p-6 sm:p-8 space-y-6">
        <h3 className="text-base font-semibold text-white flex items-center space-x-2">
          <User className="h-4 w-4 text-brand-400" />
          <span>Profile & Preferences</span>
        </h3>

        {profileMsg && (
          <div className="p-3 text-xs rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-300">
            {profileMsg}
          </div>
        )}

        <form onSubmit={handleUpdateProfile} className="space-y-4 max-w-lg">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Display Name</label>
            <input
              type="text"
              required
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full glass-input px-3.5 py-2 rounded-lg text-sm"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Theme Preference</label>
            <select
              value={theme}
              onChange={(e) => setTheme(e.target.value as any)}
              className="w-full glass-input px-3.5 py-2 rounded-lg text-sm bg-navy-900"
            >
              <option value="dark">Dark Theme (Standard)</option>
              <option value="light">Light Theme</option>
              <option value="system">System Default</option>
            </select>
          </div>

          <div className="flex items-center space-x-3 pt-2">
            <button
              type="submit"
              className="py-2 px-4 font-semibold text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 rounded-lg shadow-glow-cyan"
            >
              Save Profile
            </button>
            <button
              type="button"
              onClick={handleReplayTour}
              className="py-2 px-3 text-xs font-medium text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 rounded-lg border border-white/10 flex items-center space-x-1.5"
            >
              <RotateCcw className="h-3.5 w-3.5 text-brand-400" />
              <span>Replay Product Tour</span>
            </button>
          </div>
        </form>
      </div>

      {/* Password Management */}
      <div className="glass-panel rounded-2xl p-6 sm:p-8 space-y-6">
        <h3 className="text-base font-semibold text-white flex items-center space-x-2">
          <Lock className="h-4 w-4 text-brand-400" />
          <span>Change Password</span>
        </h3>

        {pwMsg && (
          <div
            className={`p-3 text-xs rounded-lg ${
              pwMsg.error
                ? 'bg-red-500/10 border border-red-500/30 text-red-300'
                : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
            }`}
          >
            {pwMsg.text}
          </div>
        )}

        <form onSubmit={handleChangePassword} className="space-y-4 max-w-lg">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Current Password</label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full glass-input px-3.5 py-2 rounded-lg text-sm"
              placeholder="••••••••••••"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              New Password <span className="text-slate-400 font-normal">(min. 12 characters)</span>
            </label>
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full glass-input px-3.5 py-2 rounded-lg text-sm"
              placeholder="••••••••••••"
            />
          </div>

          <button
            type="submit"
            className="py-2 px-4 font-semibold text-xs text-white bg-white/10 hover:bg-white/20 rounded-lg border border-white/10 transition-colors"
          >
            Update Password
          </button>
        </form>
      </div>

      {/* Multi-Factor Authentication */}
      <div className="glass-panel rounded-2xl p-6 sm:p-8 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-white flex items-center space-x-2">
              <Smartphone className="h-4 w-4 text-brand-400" />
              <span>Multi-Factor Authentication (TOTP)</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Protect your account using standard Google Authenticator or 1Password app
            </p>
          </div>
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
              user?.mfa_enabled
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'bg-slate-500/10 text-slate-400 border border-slate-500/30'
            }`}
          >
            {user?.mfa_enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        {mfaMsg && (
          <div
            className={`p-3 text-xs rounded-lg ${
              mfaMsg.error
                ? 'bg-red-500/10 border border-red-500/30 text-red-300'
                : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
            }`}
          >
            {mfaMsg.text}
          </div>
        )}

        {!user?.mfa_enabled && !mfaSetupData && (
          <button
            onClick={handleStartMFASetup}
            className="py-2 px-4 font-semibold text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 rounded-lg shadow-glow-cyan"
          >
            Enable Two-Factor Authentication
          </button>
        )}

        {mfaSetupData && (
          <form onSubmit={handleEnableMFA} className="space-y-4 max-w-lg bg-navy-950 p-4 rounded-xl border border-white/10">
            <span className="text-xs font-semibold text-white block">Step 1: Scan Key into Authenticator</span>
            <div className="p-2.5 rounded bg-black/40 font-mono text-xs text-cyan-300 select-all break-all">
              {mfaSetupData.secret}
            </div>
            <span className="text-xs font-semibold text-white block">Step 2: Enter 6-digit Code to Confirm</span>
            <input
              type="text"
              required
              maxLength={6}
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
              className="w-full glass-input text-center font-mono text-xl py-2 rounded-lg text-white"
              placeholder="000000"
            />
            <div className="flex space-x-2">
              <button
                type="submit"
                className="py-2 px-4 font-semibold text-xs text-white bg-brand-500 hover:bg-brand-400 rounded-lg text-navy-950"
              >
                Verify & Activate MFA
              </button>
              <button
                type="button"
                onClick={() => setMfaSetupData(null)}
                className="py-2 px-3 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Active Sessions */}
      <div className="glass-panel rounded-2xl p-6 sm:p-8 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-white flex items-center space-x-2">
              <KeyRound className="h-4 w-4 text-brand-400" />
              <span>Active Sessions</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">Manage devices currently logged into your account</p>
          </div>
          {sessions.length > 1 && (
            <button
              onClick={handleRevokeOtherSessions}
              className="text-xs text-red-400 hover:text-red-300 font-medium"
            >
              Revoke All Other Sessions
            </button>
          )}
        </div>

        <div className="space-y-2">
          {sessions.map((s) => (
            <div
              key={s.id}
              className="flex items-center justify-between p-3.5 rounded-lg bg-navy-950/60 border border-white/5 text-xs font-mono"
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="text-white font-medium">{s.ip_address || 'Unknown IP'}</span>
                  {s.current && (
                    <span className="bg-brand-500/20 text-brand-400 border border-brand-500/30 text-[10px] px-1.5 py-0.2 rounded uppercase">
                      Current Device
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-slate-400 truncate max-w-sm">
                  {s.user_agent || 'Unknown Client'}
                </div>
              </div>

              <div>
                {!s.current && (
                  <button
                    onClick={() => handleRevokeSession(s.id)}
                    className="text-xs text-red-400 hover:text-red-300 px-2 py-1 rounded bg-red-500/10 hover:bg-red-500/20"
                  >
                    Revoke
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Export & Deletion */}
      <div className="glass-panel rounded-2xl p-6 sm:p-8 space-y-6 border-red-500/20">
        <h3 className="text-base font-semibold text-white flex items-center space-x-2">
          <Download className="h-4 w-4 text-brand-400" />
          <span>Account Data Export & Erasure</span>
        </h3>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-navy-950/60 border border-white/5">
          <div>
            <span className="text-xs font-semibold text-white block">Download Account Archive</span>
            <span className="text-[11px] text-slate-400">Export your profile, organizations, audit events, and reports in JSON</span>
          </div>
          <button
            onClick={handleExportData}
            className="py-1.5 px-3 text-xs font-medium text-white bg-white/10 hover:bg-white/20 rounded-lg shrink-0"
          >
            Export JSON
          </button>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
          <div>
            <span className="text-xs font-semibold text-red-300 block">Schedule Account Deletion</span>
            <span className="text-[11px] text-red-400/80">Permanent removal of all personal projects, artifacts, and scan history</span>
          </div>
          <button
            onClick={() => setShowDeleteModal(true)}
            className="py-1.5 px-3 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg shrink-0"
          >
            Request Deletion
          </button>
        </div>
      </div>

      {/* Deletion Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-md">
          <div className="glass-panel w-full max-w-md p-6 rounded-2xl border border-red-500/30 space-y-4">
            <h3 className="text-lg font-bold text-white">Confirm Account Deletion</h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              This action signs out all active sessions and schedules irreversible data deletion. Enter your credentials to confirm:
            </p>

            {deleteError && (
              <div className="p-2 rounded bg-red-500/20 text-red-300 text-xs">
                {deleteError}
              </div>
            )}

            <form onSubmit={handleDeleteAccount} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Confirm Password</label>
                <input
                  type="password"
                  required
                  value={deletePassword}
                  onChange={(e) => setDeletePassword(e.target.value)}
                  className="w-full glass-input px-3.5 py-2 rounded-lg text-sm"
                  placeholder="••••••••••••"
                />
              </div>

              {user?.mfa_enabled && (
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">6-digit MFA Code</label>
                  <input
                    type="text"
                    required
                    maxLength={6}
                    value={deleteCode}
                    onChange={(e) => setDeleteCode(e.target.value.replace(/\D/g, ''))}
                    className="w-full glass-input px-3.5 py-2 rounded-lg text-sm font-mono text-center"
                    placeholder="000000"
                  />
                </div>
              )}

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowDeleteModal(false)}
                  className="py-1.5 px-3 text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="py-1.5 px-4 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg"
                >
                  Confirm Delete
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
