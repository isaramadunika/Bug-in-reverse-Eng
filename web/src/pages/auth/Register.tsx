import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { apiRequest } from '../../lib/api';
import { ShieldAlert, ArrowRight, Lock, Mail, User, CheckCircle2, AlertCircle } from 'lucide-react';

export const Register: React.FC = () => {
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [acceptTerms, setAcceptTerms] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldErrors({});
    setLoading(true);

    try {
      await apiRequest('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          email,
          display_name: displayName,
          password,
          accept_terms: acceptTerms,
        }),
      });

      setSuccess(true);
    } catch (err: any) {
      setError(err.message || 'Registration failed.');
      if (err.fields) {
        setFieldErrors(err.fields);
      }
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
          <h2 className="text-2xl font-bold text-white">Check Your Inbox</h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            We have dispatched a verification link to <strong className="text-white font-mono">{email}</strong>. Click the link within 24 hours to activate your account.
          </p>
          <div className="pt-4 border-t border-white/10">
            <Link
              to="/login"
              className="inline-flex items-center justify-center px-4 py-2 text-xs font-semibold text-white bg-white/10 hover:bg-white/20 rounded-lg transition-colors"
            >
              Return to Sign In
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12">
      <div className="w-full max-w-md space-y-6 glass-panel p-8 sm:p-10 rounded-2xl border border-white/10 shadow-glass">
        <div className="text-center space-y-2">
          <div className="h-10 w-10 mx-auto rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white">Create ReverseBug Account</h2>
          <p className="text-xs text-slate-400">Start free Android reverse engineering & vulnerability assessment</p>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-start space-x-2 text-xs text-red-300">
            <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
            <div className="relative">
              <User className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="text"
                required
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full glass-input pl-9 pr-3 py-2 rounded-lg text-sm"
                placeholder="Jane Doe"
              />
            </div>
            {fieldErrors.display_name && (
              <p className="text-[11px] text-red-400 mt-1">{fieldErrors.display_name}</p>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Corporate or Research Email</label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full glass-input pl-9 pr-3 py-2 rounded-lg text-sm"
                placeholder="analyst@company.com"
              />
            </div>
            {fieldErrors.email && (
              <p className="text-[11px] text-red-400 mt-1">{fieldErrors.email}</p>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Password <span className="text-slate-400 font-normal">(min. 12 characters)</span>
            </label>
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
            {fieldErrors.password && (
              <p className="text-[11px] text-red-400 mt-1">{fieldErrors.password}</p>
            )}
          </div>

          <div className="flex items-start space-x-2 pt-1">
            <input
              type="checkbox"
              id="terms"
              required
              checked={acceptTerms}
              onChange={(e) => setAcceptTerms(e.target.checked)}
              className="mt-1 h-4 w-4 rounded bg-navy-900 border-white/20 text-brand-500 focus:ring-brand-400"
            />
            <label htmlFor="terms" className="text-xs text-slate-300 leading-normal">
              I certify that I will evaluate only authorized applications in compliance with the{' '}
              <Link to="/acceptable-use" target="_blank" className="text-brand-400 underline">
                Acceptable Use Policy
              </Link>{' '}
              and{' '}
              <Link to="/terms" target="_blank" className="text-brand-400 underline">
                Terms of Service
              </Link>.
            </label>
          </div>
          {fieldErrors.accept_terms && (
            <p className="text-[11px] text-red-400">{fieldErrors.accept_terms}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full inline-flex items-center justify-center py-2.5 px-4 font-semibold text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-lg shadow-glow-cyan transition-all disabled:opacity-50"
          >
            {loading ? (
              <span>Creating Account...</span>
            ) : (
              <>
                <span>Register & Continue</span>
                <ArrowRight className="h-3.5 w-3.5 ml-1.5" />
              </>
            )}
          </button>
        </form>

        <div className="text-center text-xs text-slate-400 pt-2 border-t border-white/5">
          Already have an account?{' '}
          <Link to="/login" className="text-brand-400 hover:text-brand-300 font-medium">
            Sign In
          </Link>
        </div>
      </div>
    </div>
  );
};
