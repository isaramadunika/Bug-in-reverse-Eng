import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiRequest } from '../../lib/api';
import { 
  FolderPlus, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  Layers, 
  Clock, 
  ArrowRight,
  Plus,
  RefreshCw,
  Cpu
} from 'lucide-react';

interface ProjectSummary {
  id: string;
  name: string;
  description: string;
  package_name: string | null;
  application_owner: string;
  environment: string;
  tags: string[];
  scan_count: number;
  latest_score: number | null;
  latest_scan_status: string | null;
  latest_scan_at: string | null;
  has_active_auth: boolean;
  active_auth_record_id: string | null;
  created_at: string;
  updated_at: string;
}

export const Projects: React.FC = () => {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);

  // New project form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [packageName, setPackageName] = useState('');
  const [environment, setEnvironment] = useState('production');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const fetchProjects = () => {
    setLoading(true);
    apiRequest<{ projects: ProjectSummary[] }>('/projects', { method: 'GET' })
      .then((res) => setProjects(res.projects || []))
      .catch((err) => console.error('Failed to load projects', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setCreateError(null);
    try {
      await apiRequest('/projects', {
        method: 'POST',
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim(),
          package_name: packageName.trim() || undefined,
          environment,
          tags: ['android', environment],
        }),
      });
      setShowCreateModal(false);
      setName('');
      setDescription('');
      setPackageName('');
      fetchProjects();
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create project');
    } finally {
      setCreating(false);
    }
  };

  const filtered = projects.filter(
    (p) =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      (p.package_name && p.package_name.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Layers className="h-6 w-6 text-brand-400" />
            <span>Target Projects</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage Android applications, verified attestations of authorization, and security histories.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchProjects}
            className="p-2 text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 rounded-lg border border-white/10 transition-colors"
            title="Refresh Projects"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin text-brand-400' : ''}`} />
          </button>

          <button
            onClick={() => setShowCreateModal(true)}
            className="btn-primary text-xs py-2 px-4 flex items-center space-x-2 rounded-lg"
          >
            <Plus className="h-4 w-4" />
            <span>Create Project</span>
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="flex items-center space-x-3 max-w-md">
        <div className="relative w-full">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search projects by name or package..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 transition-colors"
          />
        </div>
      </div>

      {/* Projects Grid */}
      {loading ? (
        <div className="h-64 flex items-center justify-center">
          <div className="h-8 w-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass-card rounded-2xl p-12 text-center space-y-4">
          <div className="h-12 w-12 rounded-xl bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 mx-auto">
            <FolderPlus className="h-6 w-6" />
          </div>
          <div className="max-w-sm mx-auto space-y-1">
            <h3 className="text-base font-semibold text-white">No projects found</h3>
            <p className="text-xs text-slate-400">
              {search ? 'Try adjusting your search query.' : 'Create your first Android reverse engineering project to begin.'}
            </p>
          </div>
          {!search && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn-primary text-xs py-2 px-4 rounded-lg inline-flex items-center space-x-2"
            >
              <Plus className="h-4 w-4" />
              <span>Create Project</span>
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filtered.map((proj) => (
            <Link
              key={proj.id}
              to={`/projects/${proj.id}`}
              className="glass-card p-6 rounded-2xl flex flex-col justify-between hover:border-brand-500/40 transition-all group"
            >
              <div className="space-y-4">
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-brand-400 bg-brand-500/10 px-2 py-0.5 rounded border border-brand-500/20">
                      {proj.environment}
                    </span>
                    <h3 className="text-base font-bold text-white group-hover:text-brand-300 transition-colors">
                      {proj.name}
                    </h3>
                  </div>

                  {/* Security Score Badge */}
                  {proj.latest_score !== null ? (
                    <div className="text-right">
                      <div className={`text-xl font-mono font-bold ${
                        proj.latest_score >= 80 ? 'text-emerald-400' :
                        proj.latest_score >= 60 ? 'text-amber-400' : 'text-rose-400'
                      }`}>
                        {proj.latest_score}
                      </div>
                      <span className="text-[9px] text-slate-500 uppercase tracking-wider">Score</span>
                    </div>
                  ) : (
                    <span className="text-xs font-mono text-slate-500">Unscored</span>
                  )}
                </div>

                <p className="text-xs text-slate-400 line-clamp-2">
                  {proj.description || 'No description provided.'}
                </p>

                {proj.package_name && (
                  <div className="text-[11px] font-mono text-slate-400 truncate bg-black/30 px-2 py-1 rounded">
                    {proj.package_name}
                  </div>
                )}
              </div>

              {/* Footer Details */}
              <div className="pt-6 border-t border-white/5 flex items-center justify-between text-xs text-slate-400">
                <div className="flex items-center space-x-2">
                  {proj.has_active_auth ? (
                    <span className="flex items-center space-x-1 text-emerald-400 font-medium text-[11px]">
                      <ShieldCheck className="h-3.5 w-3.5" />
                      <span>Authorized</span>
                    </span>
                  ) : (
                    <span className="flex items-center space-x-1 text-amber-400 font-medium text-[11px]">
                      <ShieldAlert className="h-3.5 w-3.5" />
                      <span>Attestation Required</span>
                    </span>
                  )}
                </div>

                <div className="flex items-center space-x-1 group-hover:translate-x-1 transition-transform text-brand-400 text-xs font-medium">
                  <span>{proj.scan_count} Scans</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}

      {/* Create Project Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm">
          <div className="glass-card rounded-2xl max-w-md w-full p-6 space-y-6 border border-white/20 animate-fade-in">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                <FolderPlus className="h-5 w-5 text-brand-400" />
                <span>Create New Project</span>
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            {createError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreate} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Project Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Mobile Banking"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Expected Package Name (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. com.acme.banking.app"
                  value={packageName}
                  onChange={(e) => setPackageName(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Environment</label>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white focus:outline-none focus:border-brand-500"
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Description</label>
                <textarea
                  rows={3}
                  placeholder="Brief description of application scope, security objectives, or penetration test parameters."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-500"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-4 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="btn-primary text-xs py-2 px-5 rounded-lg flex items-center space-x-2"
                >
                  {creating && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                  <span>{creating ? 'Creating...' : 'Create Project'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
