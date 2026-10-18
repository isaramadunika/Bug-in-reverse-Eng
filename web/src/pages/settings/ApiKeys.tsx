import React, { useEffect, useState } from 'react';
import { apiRequest } from '../../lib/api';
import {
  Key,
  Plus,
  Copy,
  Check,
  Trash2,
  ShieldAlert,
  Clock,
  Terminal,
  Activity,
  AlertTriangle,
  Lock,
  Code2
} from 'lucide-react';

interface APIKeyItem {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  usage_count: number;
  last_used_at?: string;
  last_used_ip?: string;
  expires_at?: string;
  revoked_at?: string;
  created_at: string;
}

export const ApiKeys: React.FC = () => {
  const [keys, setKeys] = useState<APIKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Creation modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [keyName, setKeyName] = useState('');
  const [expiresInDays, setExpiresInDays] = useState('30');
  const [selectedScopes, setSelectedScopes] = useState<string[]>([
    'scans:read',
    'scans:write',
    'projects:read',
    'reports:read',
  ]);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // One-time newly generated secret modal
  const [newKeySecret, setNewKeySecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Revoke state
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const fetchKeys = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await apiRequest<{ items: APIKeyItem[] }>('/api-keys');
      setKeys(res.items || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load API keys.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyName.trim()) {
      setCreateError('Please provide a key name.');
      return;
    }
    try {
      setCreating(true);
      setCreateError(null);
      const res = await apiRequest<{ token: string; api_key: APIKeyItem }>('/api-keys', {
        method: 'POST',
        body: JSON.stringify({
          name: keyName.trim(),
          scopes: selectedScopes,
          expires_in_days: parseInt(expiresInDays, 10),
        }),
      });
      setNewKeySecret(res.token);
      setShowCreateModal(false);
      setKeyName('');
      await fetchKeys();
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create API key.');
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (keyId: string) => {
    if (!window.confirm('Are you sure you want to revoke this API key? Any automated pipelines using it will immediately fail.')) {
      return;
    }
    try {
      setRevokingId(keyId);
      await apiRequest(`/api-keys/${keyId}`, { method: 'DELETE' });
      await fetchKeys();
    } catch (err: any) {
      alert(err.message || 'Failed to revoke API key.');
    } finally {
      setRevokingId(null);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const toggleScope = (scope: string) => {
    if (selectedScopes.includes(scope)) {
      setSelectedScopes(selectedScopes.filter((s) => s !== scope));
    } else {
      setSelectedScopes([...selectedScopes, scope]);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-white/10">
        <div>
          <div className="flex items-center space-x-2">
            <Key className="h-6 w-6 text-brand-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">API Keys & Tokens</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Programmatic Bearer authentication for automated CI/CD pipelines, DevSecOps runners, and SDK integrations.
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-brand-600 to-cyan-500 hover:from-brand-500 hover:to-cyan-400 text-white text-xs font-semibold rounded-lg shadow-glow-cyan transition-all"
        >
          <Plus className="h-4 w-4" />
          <span>Generate New Key</span>
        </button>
      </div>

      {/* Security Architecture Callout */}
      <div className="bg-navy-900/60 border border-brand-500/20 rounded-xl p-4 sm:p-5 flex items-start space-x-4">
        <div className="p-2 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-400 shrink-0">
          <Lock className="h-5 w-5" />
        </div>
        <div className="text-xs text-slate-300 space-y-1">
          <p className="font-semibold text-white">Zero-Knowledge Token Architecture</p>
          <p className="text-slate-400 leading-relaxed">
            ReverseBug API keys are authenticated using timing-safe HMAC-SHA256 comparison against a server-side pepper (<code className="text-cyan-300">RB_API_KEY_PEPPER</code>). Raw tokens are never stored plaintext in our authoritative database and cannot be retrieved after initial creation.
          </p>
        </div>
      </div>

      {/* Keys Table */}
      <div className="bg-navy-900/50 border border-white/10 rounded-xl overflow-hidden shadow-xl">
        <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
            Active Credentials ({keys.filter((k) => !k.revoked_at).length})
          </h2>
          <span className="text-xs text-slate-400">Total keys: {keys.length}</span>
        </div>

        {loading ? (
          <div className="p-12 text-center">
            <div className="h-8 w-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            <p className="text-xs text-slate-400">Loading API keys...</p>
          </div>
        ) : error ? (
          <div className="p-6 text-center text-red-400 text-sm">{error}</div>
        ) : keys.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <Code2 className="h-10 w-10 text-slate-600 mx-auto" />
            <p className="text-slate-300 font-medium">No API keys created yet</p>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Create an API key to run scans from GitHub Actions, GitLab CI, or custom CLI scripts.
            </p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="mt-2 inline-flex items-center space-x-1.5 px-3.5 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-md text-xs text-brand-300 transition-colors"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>Create your first key</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-navy-950/80 text-slate-400 uppercase font-mono tracking-wider text-[11px] border-b border-white/10">
                <tr>
                  <th className="py-3 px-6">Name / Identifier</th>
                  <th className="py-3 px-4">Prefix</th>
                  <th className="py-3 px-4">Scopes</th>
                  <th className="py-3 px-4">Usage Count</th>
                  <th className="py-3 px-4">Last Used</th>
                  <th className="py-3 px-4">Expires</th>
                  <th className="py-3 px-6 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300">
                {keys.map((k) => {
                  const isRevoked = !!k.revoked_at;
                  return (
                    <tr key={k.id} className={`hover:bg-white/[0.02] transition-colors ${isRevoked ? 'opacity-50' : ''}`}>
                      <td className="py-4 px-6">
                        <div className="font-medium text-white flex items-center space-x-2">
                          <span>{k.name}</span>
                          {isRevoked && (
                            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                              Revoked
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                          Created {new Date(k.created_at).toLocaleDateString()}
                        </div>
                      </td>
                      <td className="py-4 px-4 font-mono text-cyan-300">
                        {k.prefix}...
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {k.scopes.map((sc) => (
                            <span key={sc} className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[10px] text-slate-300 font-mono">
                              {sc}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-4 px-4 font-mono text-slate-200">
                        {k.usage_count.toLocaleString()} calls
                      </td>
                      <td className="py-4 px-4">
                        {k.last_used_at ? (
                          <div>
                            <div>{new Date(k.last_used_at).toLocaleDateString()}</div>
                            {k.last_used_ip && (
                              <div className="text-[10px] text-slate-500 font-mono">{k.last_used_ip}</div>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-500">Never</span>
                        )}
                      </td>
                      <td className="py-4 px-4 text-slate-400">
                        {k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never'}
                      </td>
                      <td className="py-4 px-6 text-right">
                        {!isRevoked && (
                          <button
                            onClick={() => handleRevoke(k.id)}
                            disabled={revokingId === k.id}
                            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors disabled:opacity-50"
                            title="Revoke API key"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Code Snippet Helper */}
      <div className="bg-navy-900/40 border border-white/10 rounded-xl p-6 space-y-4">
        <div className="flex items-center space-x-2">
          <Terminal className="h-4 w-4 text-brand-400" />
          <h3 className="text-sm font-semibold text-white">How to use your API Key</h3>
        </div>
        <p className="text-xs text-slate-400">
          Pass your secret token in either the standard <code className="text-cyan-300">Authorization: Bearer &lt;token&gt;</code> header or the <code className="text-cyan-300">X-API-Key: &lt;token&gt;</code> header.
        </p>
        <div className="relative bg-navy-950 rounded-lg p-4 font-mono text-xs text-slate-300 border border-white/10 overflow-x-auto">
          <code>
            curl -X GET "https://api.reversebug.io/api/v1/projects" \<br />
            &nbsp;&nbsp;-H "Authorization: Bearer rb_live_YOUR_TOKEN_HERE" \<br />
            &nbsp;&nbsp;-H "Accept: application/json"
          </code>
        </div>
      </div>

      {/* Modal: Create API Key */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-navy-900 border border-white/15 rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center space-x-2">
                <Key className="h-5 w-5 text-brand-400" />
                <h3 className="text-lg font-bold text-white">Create New API Key</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            {createError && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-300 text-xs rounded-lg flex items-center space-x-2">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>{createError}</span>
              </div>
            )}

            <form onSubmit={handleCreate} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Key Description / Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. GitHub Actions CI Runner"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  className="w-full bg-navy-950 border border-white/10 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 text-xs"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Expiration Period</label>
                <select
                  value={expiresInDays}
                  onChange={(e) => setExpiresInDays(e.target.value)}
                  className="w-full bg-navy-950 border border-white/10 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-brand-500 text-xs"
                >
                  <option value="30">30 Days</option>
                  <option value="60">60 Days</option>
                  <option value="90">90 Days</option>
                  <option value="180">180 Days</option>
                  <option value="365">1 Year (365 Days)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-2">Permissions & Scopes</label>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { id: 'scans:read', label: 'scans:read', desc: 'Inspect scan results and vulnerabilities' },
                    { id: 'scans:write', label: 'scans:write', desc: 'Trigger and cancel scans' },
                    { id: 'projects:read', label: 'projects:read', desc: 'List projects and artifacts' },
                    { id: 'reports:read', label: 'reports:read', desc: 'Download PDF/HTML reports' },
                  ].map((sc) => (
                    <div
                      key={sc.id}
                      onClick={() => toggleScope(sc.id)}
                      className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                        selectedScopes.includes(sc.id)
                          ? 'bg-brand-500/10 border-brand-500/40 text-brand-300'
                          : 'bg-navy-950 border-white/5 text-slate-400 hover:border-white/20'
                      }`}
                    >
                      <div className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={selectedScopes.includes(sc.id)}
                          onChange={() => {}}
                          className="rounded border-white/20 bg-navy-900 text-brand-500 focus:ring-0"
                        />
                        <span className="font-mono font-medium">{sc.label}</span>
                      </div>
                      <p className="text-[10px] text-slate-500 mt-1 pl-5">{sc.desc}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-3 border-t border-white/10 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-white/5 hover:bg-white/10 text-slate-300 rounded-lg text-xs transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 bg-gradient-to-r from-brand-600 to-cyan-500 hover:from-brand-500 hover:to-cyan-400 text-white font-medium rounded-lg shadow-glow-cyan text-xs transition-all disabled:opacity-50"
                >
                  {creating ? 'Generating...' : 'Create Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Secret Display Warning (One-Time Display) */}
      {newKeySecret && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-navy-900 border border-amber-500/40 rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl animate-in zoom-in-95">
            <div className="flex items-center space-x-3 text-amber-400">
              <ShieldAlert className="h-6 w-6 shrink-0" />
              <div>
                <h3 className="text-lg font-bold text-white">Save Your API Key Now</h3>
                <p className="text-xs text-amber-300/80">
                  This key will never be shown again once you close this window.
                </p>
              </div>
            </div>

            <div className="bg-navy-950 border border-white/15 rounded-xl p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">Secret Token</span>
                <button
                  onClick={() => copyToClipboard(newKeySecret)}
                  className="inline-flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copied ? 'Copied to Clipboard!' : 'Copy'}</span>
                </button>
              </div>
              <div className="font-mono text-xs text-emerald-300 break-all select-all bg-black/40 p-2.5 rounded-lg border border-white/5">
                {newKeySecret}
              </div>
            </div>

            <div className="text-xs text-slate-400 leading-relaxed">
              Store this token in a secure secrets manager such as GitHub Secrets, HashiCorp Vault, or AWS Secrets Manager. Never commit it to public version control.
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setNewKeySecret(null)}
                className="px-5 py-2 bg-white/10 hover:bg-white/15 text-white font-medium rounded-lg text-xs transition-colors"
              >
                I Have Saved My Key
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
