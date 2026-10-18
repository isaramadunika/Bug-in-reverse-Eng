import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { apiRequest } from '../../lib/api';
import { ShieldCheck, ArrowRight, AlertCircle } from 'lucide-react';

export const MFAVerify: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const resp = await apiRequest<any>('/auth/mfa/verify', {
        method: 'POST',
        body: JSON.stringify({ code: code.trim() }),
      });

      login(resp);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Invalid or expired 6-digit MFA code.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md space-y-6 glass-panel p-8 sm:p-10 rounded-2xl border border-white/10 shadow-glass text-center">
        <div className="h-10 w-10 mx-auto rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400">
          <ShieldCheck className="h-6 w-6" />
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Two-Factor Authentication</h2>
        <p className="text-xs text-slate-400">
          Enter the 6-digit verification code from your authenticator application
        </p>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-start space-x-2 text-xs text-red-300 text-left">
            <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <input
              type="text"
              required
              maxLength={6}
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              className="w-full glass-input text-center font-mono text-2xl tracking-[0.5em] py-3 rounded-lg text-white"
              placeholder="000000"
            />
          </div>

          <button
            type="submit"
            disabled={loading || code.length !== 6}
            className="w-full inline-flex items-center justify-center py-2.5 px-4 font-semibold text-xs text-white bg-gradient-to-r from-brand-600 to-blue-600 hover:from-brand-500 hover:to-blue-500 rounded-lg shadow-glow-cyan transition-all disabled:opacity-50"
          >
            {loading ? <span>Verifying...</span> : <span>Confirm & Sign In</span>}
          </button>
        </form>
      </div>
    </div>
  );
};
