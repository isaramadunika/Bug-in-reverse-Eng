import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { apiRequest } from '../../lib/api';
import { 
  Layers, 
  Upload, 
  Link as LinkIcon, 
  ShieldCheck, 
  ShieldAlert, 
  Play, 
  Cpu, 
  Clock, 
  FileCode, 
  FileCheck, 
  AlertTriangle, 
  ArrowLeft,
  CheckCircle2,
  RefreshCw,
  Copy,
  ExternalLink
} from 'lucide-react';

interface ProjectDetailData {
  id: string;
  name: string;
  description: string;
  package_name: string | null;
  application_owner: string;
  environment: string;
  tags: string[];
  scan_count: number;
  latest_score: number | null;
  has_active_auth: boolean;
  active_auth_record_id: string | null;
  created_at?: string;
  active_authorization?: {
    id: string;
    basis: string;
    scope_description: string;
    allows_dynamic_validation: boolean;
    reference_url: string | null;
    created_at: string;
    attestor_name?: string;
  };
}

interface ArtifactVersion {
  id: string;
  original_filename: string;
  source: string;
  source_url: string | null;
  package_name: string | null;
  version_name: string | null;
  version_code: number | null;
  min_sdk: number | null;
  target_sdk: number | null;
  permissions: string[];
  created_at: string;
}

interface ScanSummary {
  id: string;
  profile_id: string;
  status: string;
  security_score: number | null;
  findings_count: number;
  original_filename: string;
  package_name: string | null;
  version_name: string | null;
  created_at: string;
  finished_at: string | null;
}

export const ProjectDetail: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();

  const [project, setProject] = useState<ProjectDetailData | null>(null);
  const [artifacts, setArtifacts] = useState<ArtifactVersion[]>([]);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'artifacts' | 'authorization' | 'scans'>('overview');

  // Upload state
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // URL Import state
  const [importUrl, setImportUrl] = useState('');
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  // Authorization Form State
  const [authBasis, setAuthBasis] = useState('client_contract');
  const [scopeDesc, setScopeDesc] = useState('');
  const [refUrl, setRefUrl] = useState('');
  const [allowsDynamic, setAllowsDynamic] = useState(false);
  const [legalConfirmed, setLegalConfirmed] = useState(false);
  const [submittingAuth, setSubmittingAuth] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  // Scan Launch State
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedArtifactId, setSelectedArtifactId] = useState<string>('');
  const [selectedProfile, setSelectedProfile] = useState<'quick' | 'standard' | 'deep'>('standard');
  const [launchingScan, setLaunchingScan] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const loadData = () => {
    if (!projectId) return;
    setLoading(true);

    Promise.all([
      apiRequest<{ project: ProjectDetailData }>(`/projects/${projectId}`),
      apiRequest<{ artifacts: ArtifactVersion[] }>(`/projects/${projectId}/artifacts`),
      apiRequest<{ scans: ScanSummary[] }>(`/projects/${projectId}/scans`),
    ])
      .then(([pRes, aRes, sRes]) => {
        setProject(pRes.project);
        setArtifacts(aRes.artifacts || []);
        setScans(sRes.scans || []);
        if (aRes.artifacts?.length && !selectedArtifactId) {
          setSelectedArtifactId(aRes.artifacts[0].id);
        }
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, [projectId]);

  // Handle APK upload
  const handleFileUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || !projectId) return;

    setUploading(true);
    setUploadError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      await apiRequest(`/projects/${projectId}/artifacts/uploads`, {
        method: 'POST',
        body: formData,
      });
      setFile(null);
      loadData();
      setActiveTab('artifacts');
    } catch (err: any) {
      setUploadError(err.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  // Handle URL import
  const handleUrlImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importUrl || !projectId) return;

    setImporting(true);
    setImportError(null);

    try {
      await apiRequest(`/projects/${projectId}/artifacts/import-url`, {
        method: 'POST',
        body: JSON.stringify({ url: importUrl.trim() }),
      });
      setImportUrl('');
      loadData();
      setActiveTab('artifacts');
    } catch (err: any) {
      setImportError(err.message || 'Remote URL import failed');
    } finally {
      setImporting(false);
    }
  };

  // Handle Authorization recording
  const handleAuthorize = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!legalConfirmed || !projectId) return;

    setSubmittingAuth(true);
    setAuthError(null);

    try {
      await apiRequest(`/projects/${projectId}/authorizations`, {
        method: 'POST',
        body: JSON.stringify({
          basis: authBasis,
          scope_description: scopeDesc.trim(),
          allows_dynamic_validation: allowsDynamic,
          reference_url: refUrl.trim() || undefined,
        }),
      });
      loadData();
      setActiveTab('overview');
    } catch (err: any) {
      setAuthError(err.message || 'Attestation submission failed');
    } finally {
      setSubmittingAuth(false);
    }
  };

  // Handle Scan initiation
  const handleStartScan = async () => {
    if (!projectId || !selectedArtifactId) return;

    setLaunchingScan(true);
    setScanError(null);

    try {
      const res = await apiRequest<{ scan: { id: string } }>(`/projects/${projectId}/scans`, {
        method: 'POST',
        body: JSON.stringify({
          artifact_version_id: selectedArtifactId,
          profile_id: selectedProfile,
        }),
      });
      setShowScanModal(false);
      navigate(`/scans/${res.scan.id}`);
    } catch (err: any) {
      setScanError(err.message || 'Failed to enqueue scan');
    } finally {
      setLaunchingScan(false);
    }
  };

  if (loading && !project) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="h-8 w-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="max-w-4xl mx-auto py-12 text-center text-white">
        <h3>Project not found</h3>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Breadcrumb & Navigation */}
      <div className="flex items-center space-x-2 text-xs text-slate-400">
        <Link to="/projects" className="hover:text-white flex items-center space-x-1">
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Projects</span>
        </Link>
        <span>/</span>
        <span className="text-white font-medium">{project.name}</span>
      </div>

      {/* Project Header Banner */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6 border border-white/10">
        <div className="space-y-3">
          <div className="flex items-center space-x-3">
            <span className="text-xs font-mono uppercase tracking-wider text-brand-400 bg-brand-500/10 px-2.5 py-0.5 rounded border border-brand-500/20">
              {project.environment}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Created {new Date(project.created_at || Date.now()).toLocaleDateString()}
            </span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            {project.name}
          </h1>

          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-300">
            {project.package_name && (
              <span className="font-mono bg-black/40 px-2.5 py-1 rounded border border-white/5">
                {project.package_name}
              </span>
            )}
            {project.application_owner && (
              <span>Owner: <strong className="text-white">{project.application_owner}</strong></span>
            )}
          </div>
        </div>

        {/* Action Buttons & Quick Score */}
        <div className="flex items-center space-x-4">
          {project.latest_score !== null && (
            <div className="glass-card px-5 py-3 rounded-xl text-center border border-white/10">
              <div className={`text-2xl font-mono font-bold ${
                project.latest_score >= 80 ? 'text-emerald-400' :
                project.latest_score >= 60 ? 'text-amber-400' : 'text-rose-400'
              }`}>
                {project.latest_score}
              </div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Security Score</span>
            </div>
          )}

          <button
            onClick={() => {
              if (!project.has_active_auth) {
                setActiveTab('authorization');
              } else {
                setShowScanModal(true);
              }
            }}
            className="btn-primary text-xs py-3 px-5 rounded-xl flex items-center space-x-2 font-semibold shadow-lg shadow-brand-500/20"
          >
            <Play className="h-4 w-4 fill-white" />
            <span>Launch Analysis</span>
          </button>
        </div>
      </div>

      {/* Ethical Authorization Banner */}
      {!project.has_active_auth ? (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start justify-between gap-4">
          <div className="flex items-start space-x-3">
            <ShieldAlert className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h4 className="text-xs font-bold text-amber-300 uppercase tracking-wider">
                Attestation of Authorization Required
              </h4>
              <p className="text-xs text-slate-300">
                To prevent unauthorized penetration testing and comply with security research ethics, an authorized operator must record legal scope before scans can execute.
              </p>
            </div>
          </div>
          <button
            onClick={() => setActiveTab('authorization')}
            className="btn-secondary text-xs py-1.5 px-3 rounded-lg text-amber-300 shrink-0"
          >
            Sign Attestation
          </button>
        </div>
      ) : (
        <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-between text-xs text-emerald-300">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="h-4 w-4" />
            <span>
              Authorized under basis: <strong>{project.active_authorization?.basis}</strong>
              {project.active_authorization?.attestor_name && ` by ${project.active_authorization.attestor_name}`}
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Active Authorization Active
          </span>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-white/10 flex items-center space-x-8 text-xs font-medium">
        {[
          { key: 'overview', label: 'Overview' },
          { key: 'artifacts', label: `Artifacts & APKs (${artifacts.length})` },
          { key: 'scans', label: `Scan History (${scans.length})` },
          { key: 'authorization', label: 'Legal Attestation' },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as any)}
            className={`pb-4 transition-colors relative ${
              activeTab === tab.key
                ? 'text-brand-400 font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {tab.label}
            {activeTab === tab.key && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-brand-400 rounded-full" />
            )}
          </button>
        ))}
      </div>

      {/* Tab 1: Overview */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="glass-card rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Target Profile & Scope
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                {project.description || 'No description entered for this project.'}
              </p>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 pt-4 border-t border-white/5 text-xs">
                <div>
                  <span className="text-slate-500 block">Environment</span>
                  <span className="text-white font-mono uppercase">{project.environment}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Total Scans Executed</span>
                  <span className="text-white font-mono">{project.scan_count}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Uploaded Binaries</span>
                  <span className="text-white font-mono">{artifacts.length}</span>
                </div>
              </div>
            </div>

            {/* Recent Scans List Preview */}
            <div className="glass-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Recent Analysis Runs
                </h3>
                <button
                  onClick={() => setActiveTab('scans')}
                  className="text-xs text-brand-400 hover:underline"
                >
                  View all
                </button>
              </div>

              {scans.length === 0 ? (
                <p className="text-xs text-slate-400 py-4">No scans initiated yet.</p>
              ) : (
                <div className="space-y-3">
                  {scans.slice(0, 3).map((s) => (
                    <Link
                      key={s.id}
                      to={`/scans/${s.id}`}
                      className="p-3 rounded-xl bg-white/5 hover:bg-white/10 flex items-center justify-between border border-white/5 transition-colors"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-bold text-white uppercase font-mono">
                            {s.profile_id} Scan
                          </span>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                            s.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                            s.status === 'running' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse' :
                            'bg-slate-500/10 text-slate-400'
                          }`}>
                            {s.status}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-400 font-mono block">
                          {s.original_filename} • {new Date(s.created_at).toLocaleTimeString()}
                        </span>
                      </div>

                      <div className="text-right">
                        {s.security_score !== null && (
                          <span className="text-sm font-mono font-bold text-brand-400 block">
                            {s.security_score} / 100
                          </span>
                        )}
                        <span className="text-[10px] text-slate-400">{s.findings_count} findings</span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Sidebar Quick Ingestion */}
          <div className="space-y-6">
            <div className="glass-card rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                <Upload className="h-4 w-4 text-brand-400" />
                <span>Quick APK Upload</span>
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Upload target APK with automatic ZIP-slip and compression bomb validation.
              </p>

              <form onSubmit={handleFileUpload} className="space-y-3">
                <input
                  type="file"
                  accept=".apk"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="block w-full text-xs text-slate-400 file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-brand-500/10 file:text-brand-400 hover:file:bg-brand-500/20 cursor-pointer"
                />

                {uploadError && (
                  <div className="p-2 text-rose-400 text-xs bg-rose-500/10 rounded border border-rose-500/20">
                    {uploadError}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={!file || uploading}
                  className="w-full btn-primary text-xs py-2 rounded-lg flex items-center justify-center space-x-2"
                >
                  {uploading && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                  <span>{uploading ? 'Validating & Uploading...' : 'Upload Binary'}</span>
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Artifacts */}
      {activeTab === 'artifacts' && (
        <div className="space-y-6">
          {/* Dual Ingestion Box */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* File Upload */}
            <div className="glass-card rounded-2xl p-6 space-y-4 border border-white/10">
              <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                <Upload className="h-4 w-4 text-brand-400" />
                <span>Upload APK File</span>
              </h3>
              <p className="text-xs text-slate-400">
                Direct multipart upload (up to 200MB). Central directory headers, uncompressed ratio (&lt;100:1), and manifests are inspected during quarantine ingestion.
              </p>

              <form onSubmit={handleFileUpload} className="space-y-4">
                <input
                  type="file"
                  accept=".apk"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="block w-full text-xs text-slate-400 file:mr-3 file:py-2.5 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-brand-500/10 file:text-brand-400 hover:file:bg-brand-500/20 cursor-pointer border border-white/10 rounded-xl p-2 bg-navy-900/50"
                />
                {uploadError && (
                  <div className="p-3 text-rose-400 text-xs bg-rose-500/10 rounded-lg border border-rose-500/20">
                    {uploadError}
                  </div>
                )}
                <button
                  type="submit"
                  disabled={!file || uploading}
                  className="btn-primary text-xs py-2.5 px-4 rounded-lg flex items-center space-x-2"
                >
                  {uploading && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                  <span>{uploading ? 'Processing Quarantine Upload...' : 'Upload & Validate APK'}</span>
                </button>
              </form>
            </div>

            {/* Remote URL Import */}
            <div className="glass-card rounded-2xl p-6 space-y-4 border border-white/10">
              <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                <LinkIcon className="h-4 w-4 text-cyan-400" />
                <span>SSRF-Hardened Remote URL Import</span>
              </h3>
              <p className="text-xs text-slate-400">
                Import from external public HTTPS CI/CD repositories. DNS records are pinned before dialing to strictly prohibit loopback, RFC1918, and cloud metadata (169.254.169.254) addresses.
              </p>

              <form onSubmit={handleUrlImport} className="space-y-4">
                <input
                  type="url"
                  placeholder="https://artifacts.example.com/builds/app-release.apk"
                  value={importUrl}
                  onChange={(e) => setImportUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
                {importError && (
                  <div className="p-3 text-rose-400 text-xs bg-rose-500/10 rounded-lg border border-rose-500/20">
                    {importError}
                  </div>
                )}
                <button
                  type="submit"
                  disabled={!importUrl || importing}
                  className="btn-secondary text-xs py-2.5 px-4 rounded-lg flex items-center space-x-2 text-cyan-300 border-cyan-500/30 hover:border-cyan-500"
                >
                  {importing && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                  <span>{importing ? 'Resolving & Fetching...' : 'Import Remote URL'}</span>
                </button>
              </form>
            </div>
          </div>

          {/* Artifact Versions Table */}
          <div className="glass-card rounded-2xl overflow-hidden border border-white/10">
            <div className="p-4 sm:p-6 border-b border-white/10">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Ingested Artifact Versions
              </h3>
            </div>

            {artifacts.length === 0 ? (
              <div className="p-12 text-center text-slate-400 text-xs">
                No APK binaries uploaded yet. Upload or import an APK above.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-white/5 text-slate-400 font-mono uppercase text-[10px]">
                    <tr>
                      <th className="px-6 py-3">Filename / Source</th>
                      <th className="px-6 py-3">Package / Version</th>
                      <th className="px-6 py-3">SDK Requirements</th>
                      <th className="px-6 py-3">Permissions</th>
                      <th className="px-6 py-3">Uploaded</th>
                      <th className="px-6 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-slate-300">
                    {artifacts.map((art) => (
                      <tr key={art.id} className="hover:bg-white/5 transition-colors">
                        <td className="px-6 py-4">
                          <span className="font-semibold text-white block">{art.original_filename}</span>
                          <span className="text-[10px] text-slate-500 font-mono uppercase">{art.source}</span>
                        </td>
                        <td className="px-6 py-4 font-mono text-[11px]">
                          <span className="text-brand-300 block">{art.package_name || 'Manifest Pending'}</span>
                          <span className="text-slate-400">{art.version_name ? `v${art.version_name}` : ''} {art.version_code ? `(${art.version_code})` : ''}</span>
                        </td>
                        <td className="px-6 py-4 font-mono text-[11px] text-slate-400">
                          Min: {art.min_sdk || '-'} • Target: {art.target_sdk || '-'}
                        </td>
                        <td className="px-6 py-4">
                          <span className="bg-white/5 px-2 py-0.5 rounded text-[11px] font-mono text-slate-300">
                            {art.permissions?.length || 0} permissions
                          </span>
                        </td>
                        <td className="px-6 py-4 text-slate-400 text-[11px]">
                          {new Date(art.created_at).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={() => {
                              setSelectedArtifactId(art.id);
                              setShowScanModal(true);
                            }}
                            className="btn-primary text-[11px] py-1.5 px-3 rounded-lg"
                          >
                            Analyze
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

      {/* Tab 3: Scans */}
      {activeTab === 'scans' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Comprehensive Scan Records
            </h3>
            <button
              onClick={() => setShowScanModal(true)}
              className="btn-primary text-xs py-2 px-4 rounded-lg flex items-center space-x-2"
            >
              <Play className="h-3.5 w-3.5" />
              <span>Run New Scan</span>
            </button>
          </div>

          <div className="glass-card rounded-2xl overflow-hidden border border-white/10">
            {scans.length === 0 ? (
              <div className="p-12 text-center text-slate-400 text-xs">
                No scans executed yet for this project.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-white/5 text-slate-400 font-mono uppercase text-[10px]">
                    <tr>
                      <th className="px-6 py-3">Profile</th>
                      <th className="px-6 py-3">Artifact Version</th>
                      <th className="px-6 py-3">Status</th>
                      <th className="px-6 py-3">Findings</th>
                      <th className="px-6 py-3">Security Score</th>
                      <th className="px-6 py-3">Date</th>
                      <th className="px-6 py-3 text-right">Report</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-slate-300">
                    {scans.map((s) => (
                      <tr key={s.id} className="hover:bg-white/5 transition-colors">
                        <td className="px-6 py-4">
                          <span className="font-bold text-white uppercase font-mono">{s.profile_id}</span>
                        </td>
                        <td className="px-6 py-4 font-mono text-[11px]">
                          <span className="text-slate-300 block">{s.original_filename}</span>
                          <span className="text-slate-500">{s.package_name}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                            s.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                            s.status === 'running' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse' :
                            'bg-slate-500/10 text-slate-400'
                          }`}>
                            {s.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 font-mono text-slate-300">
                          {s.findings_count}
                        </td>
                        <td className="px-6 py-4">
                          {s.security_score !== null ? (
                            <span className="text-sm font-mono font-bold text-brand-400">
                              {s.security_score}
                            </span>
                          ) : (
                            <span className="text-slate-500 font-mono">-</span>
                          )}
                        </td>
                        <td className="px-6 py-4 text-slate-400 text-[11px]">
                          {new Date(s.created_at).toLocaleString()}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <Link
                            to={`/scans/${s.id}`}
                            className="text-brand-400 hover:underline font-medium"
                          >
                            View Findings →
                          </Link>
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

      {/* Tab 4: Legal Attestation */}
      {activeTab === 'authorization' && (
        <div className="glass-card rounded-2xl p-6 sm:p-8 space-y-6 max-w-3xl border border-white/10">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center space-x-2">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
              <span>Attestation of Authorization</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Required for compliance with CFAA, GDPR, and standard ethical penetration testing rules of engagement.
            </p>
          </div>

          {authError && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 text-xs">
              {authError}
            </div>
          )}

          <form onSubmit={handleAuthorize} className="space-y-4">
            <div className="space-y-1">
              <label className="text-xs font-medium text-slate-300">Authorization Basis *</label>
              <select
                value={authBasis}
                onChange={(e) => setAuthBasis(e.target.value)}
                className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white focus:outline-none focus:border-brand-500"
              >
                <option value="owner">Direct Application Owner / Creator</option>
                <option value="employer">Employee Acting on Behalf of Organization</option>
                <option value="client_contract">Client Contract / Professional Pentest MSA</option>
                <option value="bug_bounty_program">Authorized Bug Bounty Scope</option>
                <option value="research_license">Academic Research / Permitted Software License</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-medium text-slate-300">Scope Description * (10 to 4000 chars)</label>
              <textarea
                required
                rows={3}
                placeholder="Specify target application package names, contract reference numbers, testing boundaries, and constraints."
                value={scopeDesc}
                onChange={(e) => setScopeDesc(e.target.value)}
                className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-500"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-medium text-slate-300">Reference Contract URL or Bug Bounty Program Link (Optional)</label>
              <input
                type="url"
                placeholder="https://hackerone.com/target-program or MSA reference"
                value={refUrl}
                onChange={(e) => setRefUrl(e.target.value)}
                className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-500"
              />
            </div>

            <div className="flex items-center space-x-2 pt-2">
              <input
                type="checkbox"
                id="dynamicVal"
                checked={allowsDynamic}
                onChange={(e) => setAllowsDynamic(e.target.checked)}
                className="rounded border-white/20 bg-navy-900 text-brand-500 focus:ring-0"
              />
              <label htmlFor="dynamicVal" className="text-xs text-slate-300">
                Grant permission for dynamic agent validation (sandbox emulation / intent probing)
              </label>
            </div>

            <div className="p-4 rounded-xl bg-white/5 border border-white/10 space-y-3">
              <div className="flex items-start space-x-2">
                <input
                  type="checkbox"
                  id="confirmLegal"
                  required
                  checked={legalConfirmed}
                  onChange={(e) => setLegalConfirmed(e.target.checked)}
                  className="rounded border-white/20 bg-navy-900 text-brand-500 focus:ring-0 mt-0.5"
                />
                <label htmlFor="confirmLegal" className="text-xs text-slate-300 leading-relaxed">
                  I solemnly affirm that I possess documented, explicit legal authority from the software owner to conduct reverse engineering and security vulnerability assessment on this artifact. I acknowledge that my IP address, identity, and timestamp will be immutably recorded in the platform audit ledger.
                </label>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                type="submit"
                disabled={!legalConfirmed || submittingAuth}
                className="btn-primary text-xs py-2.5 px-6 rounded-lg flex items-center space-x-2"
              >
                {submittingAuth && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                <span>{submittingAuth ? 'Recording Attestation...' : 'Sign & Submit Attestation'}</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Scan Profile Selection Modal */}
      {showScanModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm">
          <div className="glass-card rounded-2xl max-w-lg w-full p-6 space-y-6 border border-white/20 animate-fade-in">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center space-x-2">
                <Cpu className="h-5 w-5 text-brand-400" />
                <span>Configure & Launch Scan</span>
              </h3>
              <button onClick={() => setShowScanModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            {scanError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg">
                {scanError}
              </div>
            )}

            <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Target Artifact Version *</label>
                <select
                  value={selectedArtifactId}
                  onChange={(e) => setSelectedArtifactId(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-900 border border-white/10 rounded-lg text-xs text-white focus:outline-none focus:border-brand-500 font-mono"
                >
                  {artifacts.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.original_filename} ({a.package_name || 'Pending'}) - {new Date(a.created_at).toLocaleDateString()}
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-300">Scan Profile</label>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { id: 'quick', title: 'Quick', desc: 'Manifest & permissions' },
                    { id: 'standard', title: 'Standard', desc: 'Rules & secrets engine' },
                    { id: 'deep', title: 'Deep', desc: 'Full call graphs & agents' },
                  ].map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => setSelectedProfile(p.id as any)}
                      className={`p-3 rounded-xl text-left border transition-all ${
                        selectedProfile === p.id
                          ? 'border-brand-500 bg-brand-500/10 text-white'
                          : 'border-white/10 bg-white/5 text-slate-400 hover:border-white/20'
                      }`}
                    >
                      <span className="text-xs font-bold block">{p.title}</span>
                      <span className="text-[10px] text-slate-400 block mt-1">{p.desc}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-4 border-t border-white/10">
              <button
                type="button"
                onClick={() => setShowScanModal(false)}
                className="px-4 py-2 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleStartScan}
                disabled={launchingScan || !selectedArtifactId}
                className="btn-primary text-xs py-2.5 px-5 rounded-lg flex items-center space-x-2"
              >
                {launchingScan && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                <span>{launchingScan ? 'Enqueueing...' : 'Start Scan'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
