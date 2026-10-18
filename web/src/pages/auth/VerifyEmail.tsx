import React, { useEffect, useState } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { apiRequest } from '../../lib/api';
import { CheckCircle2, AlertCircle, ArrowRight, Mail } from 'lucide-react';

export const VerifyEmail: React.FC = () => {
  const [params] = useSearchParams();
  const token = params.get('token');
  const navigate = useNavigate();

  const [status, setStatus] = useState<'verifying' | 'success' | 'error'>('verifying');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [resendEmail, setResendEmail] = useState('');
  const [resendSent, setResendSent] = useState(false);

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setErrorMessage('Missing verification token. Check your email link.');
      return;
    }

    apiRequest('/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify({ token }),
    })
      .then(() => {
        setStatus('success');
      })
      .catch((err) => {
        setStatus('error');
        setErrorMessage(err.message || 'Verification token is invalid or expired.');
      });
  }, [token]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiRequest('/auth/verify-email/resend', {
        method: 'POST',
        body: JSON.stringify({ email: resendEmail }),
      });
      setResendSent(true);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to resend verification.');
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md text-center space-y-6 glass-panel p-8 sm:p-10 rounded-2xl border border-white/10 shadow-glass">
        {status === 'verifying' && (
          <div className="space-y-4">
            <div className="h-10 w-10 mx-auto border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
            <h2 className="text-xl font-bold text-white">Verifying Email Address...</h2>
            <p className="text-xs text-slate-400">Validating single-use cryptographic token</p>
          </div>
        )}

        {status === 'success' && (
          <div className="space-y-4">
            <div className="h-12 w-12 mx-auto rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="h-6 w-6" />
            </div>
            <h2 className="text-2xl font-bold text-white">Email Address Verified</h2>
            <p className="text-xs text-slate-300 leading-relaxed">
              Your ReverseBug account is now fully active. You can now sign in and begin your security analysis.
            </p>
            <div className="pt-4">
              <Link
                to="/login"
                className="w-full inline-flex items-center justify-center px-4 py-2.5 font-semibold text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-lg shadow-glow-cyan transition-all"
              >
                <span>Proceed to Sign In</span>
                <ArrowRight className="h-3.5 w-3.5 ml-1.5" />
              </Link>
            </div>
          </div>
        )}

        {status === 'error' && (
          <div className="space-y-4">
            <div className="h-12 w-12 mx-auto rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
              <AlertCircle className="h-6 w-6" />
            </div>
            <h2 className="text-xl font-bold text-white">Verification Link Expired</h2>
            <p className="text-xs text-slate-300 leading-relaxed">
              {errorMessage || 'This verification link is invalid, already consumed, or expired.'}
            </p>

            {resendSent ? (
              <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3 text-xs text-emerald-300">
                A fresh verification link has been sent if that email address exists.
              </div>
            ) : (
              <form onSubmit={handleResend} className="pt-4 space-y-3 text-left">
                <label className="block text-xs font-medium text-slate-300">Resend Verification Email</label>
                <input
                  type="email"
                  required
                  value={resendEmail}
                  onChange={(e) => setResendEmail(e.target.value)}
                  className="w-full glass-input px-3.5 py-2 rounded-lg text-sm"
                  placeholder="analyst@company.com"
                />
                <button
                  type="submit"
                  className="w-full py-2 px-4 font-semibold text-xs text-white bg-white/10 hover:bg-white/20 rounded-lg transition-colors"
                >
                  Resend Link
                </button>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
