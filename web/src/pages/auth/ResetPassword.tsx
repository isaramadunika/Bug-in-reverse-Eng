import React, { useState } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { apiRequest } from '../../lib/api';
import { ShieldAlert, Lock, ArrowRight, CheckCircle2, AlertCircle } from 'lucide-react';

export const ResetPassword: React.FC = () => {
  const [params] = useSearchParams();
  const token = params.get('token');
  const navigate = useNavigate();

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await apiRequest('/auth/password/reset', {
        method: 'POST',
        body: JSON.stringify({ token, password }),
      });
      setSuccess(true);
    } catch (err: any) {
      setError(err.message || 'Reset link is invalid or expired.');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="min-h-[80vh] flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-md text-center space-y-6 glass-panel p-8 sm:p-10 rounded-2xl border border-white/10 shadow-glass">
          <div className="h-12 w-12 mx-auto rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <CheckCircle2 className="h-6 w-6" />
          </div>
          <h2 className="text-2xl font-bold text-white">Password Changed</h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            Your password has been successfully reset. All active sessions have been signed out for security.
          </p>
          <div className="pt-4 border-t border-white/10">
            <Link
              to="/login"
              className="inline-flex items-center justify-center px-4 py-2 text-xs font-semibold text-white bg-gradient-to-r from-brand-600 to-blue-600 rounded-lg"
            >
              Sign In With New Password
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md space-y-6 glass-panel p-8 sm:p-10 rounded-2xl border border-white/10 shadow-glass text-center">
        <div className="h-10 w-10 mx-auto rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400">
          <ShieldAlert className="h-6 w-6" />
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Choose New Password</h2>
        <p className="text-xs text-slate-400">Must be at least 12 characters</p>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-start space-x-2 text-xs text-red-300 text-left">
            <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-left">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">New Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full glass-input pl-9 pr-3 py-2 rounded-lg text-sm"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Confirm New Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full glass-input pl-9 pr-3 py-2 rounded-lg text-sm"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full inline-flex items-center justify-center py-2.5 px-4 font-semibold text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-lg shadow-glow-cyan transition-all disabled:opacity-50"
          >
            {loading ? <span>Updating Password...</span> : <span>Update Password</span>}
          </button>
        </form>
      </div>
    </div>
  );
};
