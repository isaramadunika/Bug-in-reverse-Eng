import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { apiRequest } from '../../lib/api';
import { ShieldAlert, Mail, ArrowRight, CheckCircle2 } from 'lucide-react';

export const ForgotPassword: React.FC = () => {
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await apiRequest('/auth/password/forgot', {
        method: 'POST',
        body: JSON.stringify({ email }),
      });
    } finally {
      // Never reveal account existence: always show success message
      setSubmitted(true);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md space-y-6 glass-panel p-8 sm:p-10 rounded-2xl border border-white/10 shadow-glass text-center">
        <div className="h-10 w-10 mx-auto rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400">
          <ShieldAlert className="h-6 w-6" />
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Reset Password</h2>
        <p className="text-xs text-slate-400">
          Enter your registered email address to receive a single-use password recovery link.
        </p>

        {submitted ? (
          <div className="space-y-4 pt-2">
            <div className="h-12 w-12 mx-auto rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="h-6 w-6" />
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              If an active account exists for <strong className="text-white font-mono">{email}</strong>, a password reset link has been dispatched.
            </p>
            <div className="pt-4 border-t border-white/10">
              <Link to="/login" className="text-xs font-semibold text-brand-400 hover:text-brand-300">
                Return to Sign In
              </Link>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4 text-left">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Email Address</label>
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
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full inline-flex items-center justify-center py-2.5 px-4 font-semibold text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-lg shadow-glow-cyan transition-all disabled:opacity-50"
            >
              {loading ? <span>Sending Link...</span> : <span>Send Recovery Link</span>}
            </button>

            <div className="text-center pt-2">
              <Link to="/login" className="text-xs text-slate-400 hover:text-slate-200">
                Remember your password? Sign In
              </Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
