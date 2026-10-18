import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { apiRequest } from '../../lib/api';
import { 
  Cpu, 
  ArrowLeft, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  XCircle, 
  RefreshCw,
  Shield,
  Layers,
  FileCode,
  StopCircle,
  Network,
  FileText,
  Download,
  Filter,
  Search,
  Check,
  ExternalLink,
  ChevronRight,
  Bug,
  Sparkles
} from 'lucide-react';
import { EvidenceGraph, EvidenceNodeData, EvidenceEdgeData } from '../../components/graph/EvidenceGraph';
import { CodeInspector } from '../../components/inspector/CodeInspector';

interface StageEvent {
  id: number;
  stage: string;
  status: string;
  message: string | null;
  duration_ms: number | null;
  created_at: string;
}

interface ScanData {
  id: string;
  project_id: string;
  artifact_version_id: string;
  profile_id: string;
  status: string;
  current_stage: string | null;
  last_completed_stage: string | null;
  progress_numerator: number | null;
  progress_denominator: number | null;
  failure_reason: string | null;
  security_score: number | null;
  score_state: string | null;
  score_breakdown: any;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  original_filename: string;
  package_name: string | null;
  version_name: string | null;
  findings_count: number;
  stages: StageEvent[];
}

interface FindingOccurrence {
  id: string;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  component_name: string | null;
}

interface EvidenceItem {
  id: string;
  location: string | null;
  line_start: number | null;
  line_end: number | null;
  excerpt: string;
  confidence: string;
  verification_status: string;
}

interface Finding {
  id: string;
  scan_id: string;
  fingerprint: string;
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  verification_status: string;
  reachability: string;
  category: string;
  cwe_ids: string[];
  masvs_ids: string[];
  impact: string;
  preconditions: string;
  remediation: string;
  review_status: string;
  include_in_report: boolean;
  created_at: string;
  occurrences?: FindingOccurrence[];
  evidence?: EvidenceItem[];
}

interface ReportItem {
  id: string;
  scan_id: string;
  format: string;
  status: string;
  sha256: string | null;
  size_bytes: number | null;
  created_at: string;
  ready_at: string | null;
}

export const ScanDetail: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [cancelling, setCancelling] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'graph' | 'inspector' | 'reports'>('overview');

  // Findings state
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Evidence Graph state
  const [graphNodes, setGraphNodes] = useState<EvidenceNodeData[]>([]);
  const [graphEdges, setGraphEdges] = useState<EvidenceEdgeData[]>([]);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [selectedGraphNode, setSelectedGraphNode] = useState<EvidenceNodeData | null>(null);

  // Code Inspector target state
  const [inspectorFile, setInspectorFile] = useState<string>('AndroidManifest.xml');
  const [inspectorLineStart, setInspectorLineStart] = useState<number | undefined>(undefined);
  const [inspectorLineEnd, setInspectorLineEnd] = useState<number | undefined>(undefined);
  const [inspectorTitle, setInspectorTitle] = useState<string | undefined>(undefined);

  // Reports state
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [generatingReport, setGeneratingReport] = useState<string | null>(null);

  const fetchScan = () => {
    if (!scanId) return;
    apiRequest<{ scan: ScanData }>(`/scans/${scanId}`, { method: 'GET' })
      .then((res) => setScan(res.scan))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  const fetchFindings = () => {
    if (!scanId) return;
    setLoadingFindings(true);
    let url = `/scans/${scanId}/findings?`;
    if (severityFilter !== 'all') url += `severity=${severityFilter}&`;
    if (statusFilter !== 'all') url += `review_status=${statusFilter}&`;
    if (searchQuery) url += `search=${encodeURIComponent(searchQuery)}&`;

    apiRequest<{ findings: Finding[] }>(url, { method: 'GET' })
      .then((res) => {
        setFindings(res.findings || []);
        if (res.findings?.length > 0 && !selectedFinding) {
          fetchFindingDetail(res.findings[0].id);
        }
      })
      .catch((err) => console.error(err))
      .finally(() => setLoadingFindings(false));
  };

  const fetchFindingDetail = (findingId: string) => {
    apiRequest<{ finding: Finding }>(`/findings/${findingId}`, { method: 'GET' })
      .then((res) => setSelectedFinding(res.finding))
      .catch((err) => console.error(err));
  };

  const fetchGraph = () => {
    if (!scanId) return;
    setLoadingGraph(true);
    apiRequest<{ nodes: EvidenceNodeData[]; edges: EvidenceEdgeData[] }>(`/scans/${scanId}/evidence-graph`, {
      method: 'GET',
    })
      .then((res) => {
        setGraphNodes(res.nodes || []);
        setGraphEdges(res.edges || []);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoadingGraph(false));
  };

  const fetchReports = () => {
    if (!scanId) return;
    apiRequest<{ reports: ReportItem[] }>(`/scans/${scanId}/reports`, { method: 'GET' })
      .then((res) => setReports(res.reports || []))
      .catch((err) => console.error(err));
  };

  useEffect(() => {
    fetchScan();
    const interval = setInterval(() => {
      if (scan?.status === 'queued' || scan?.status === 'running') {
        fetchScan();
      }
    }, 2500);
    return () => clearInterval(interval);
  }, [scanId, scan?.status]);

  useEffect(() => {
    if (activeTab === 'findings') {
      fetchFindings();
    } else if (activeTab === 'graph') {
      fetchGraph();
    } else if (activeTab === 'reports') {
      fetchReports();
    }
  }, [activeTab, scanId, severityFilter, statusFilter]);

  const handleCancel = async () => {
    if (!scanId) return;
    setCancelling(true);
    try {
      await apiRequest(`/scans/${scanId}/cancel`, { method: 'POST' });
      fetchScan();
    } catch (err: any) {
      alert(err.message || 'Failed to cancel scan');
    } finally {
      setCancelling(false);
    }
  };

  const handleUpdateFindingStatus = async (findingId: string, newStatus: string) => {
    try {
      const res = await apiRequest<{ finding: Finding }>(`/findings/${findingId}`, {
        method: 'PATCH',
        body: JSON.stringify({ review_status: newStatus }),
      });
      // Update local findings state
      setFindings((prev) => prev.map((f) => (f.id === findingId ? { ...f, review_status: newStatus } : f)));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(res.finding);
      }
    } catch (err: any) {
      alert(err.message || 'Failed to update finding status');
    }
  };

  const handleInspectFinding = (finding: Finding) => {
    const occ = finding.occurrences?.[0];
    const ev = finding.evidence?.[0];
    const filePath = occ?.file_path || ev?.location || 'AndroidManifest.xml';
    const lineStart = occ?.line_start || ev?.line_start || undefined;
    const lineEnd = occ?.line_end || ev?.line_end || undefined;

    setInspectorFile(filePath);
    setInspectorLineStart(lineStart);
    setInspectorLineEnd(lineEnd);
    setInspectorTitle(`${finding.rule_id} — ${finding.title}`);
    setActiveTab('inspector');
  };

  const handleGenerateReport = async (format: 'json' | 'pdf') => {
    if (!scanId) return;
    setGeneratingReport(format);
    try {
      await apiRequest(`/scans/${scanId}/reports`, {
        method: 'POST',
        body: JSON.stringify({ format }),
      });
      fetchReports();
    } catch (err: any) {
      alert(err.message || 'Failed to generate report');
    } finally {
      setGeneratingReport(null);
    }
  };

  if (loading && !scan) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="h-8 w-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="max-w-4xl mx-auto py-12 text-center text-white">
        <h3>Scan record not found</h3>
        <Link to="/projects" className="text-brand-400 hover:underline mt-4 inline-block">
          Return to Projects
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Navigation & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <Link
            to={`/projects/${scan.project_id}`}
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition mb-2"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Project</span>
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <Cpu className="w-6 h-6 text-brand-400" />
              <span>Security Scan Analysis</span>
            </h1>
            <span
              className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider ${
                scan.status === 'completed'
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  : scan.status === 'running'
                  ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30 animate-pulse'
                  : scan.status === 'failed'
                  ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                  : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
              }`}
            >
              {scan.status}
            </span>
          </div>
          <div className="text-xs text-slate-400 mt-1 flex items-center gap-2 font-mono">
            <span>ID: {scan.id}</span>
            <span>&bull;</span>
            <span className="text-cyan-400">{scan.package_name || scan.original_filename}</span>
            <span>&bull;</span>
            <span>Profile: {scan.profile_id}</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {scan.status === 'running' && (
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 transition disabled:opacity-50"
            >
              <StopCircle className="w-3.5 h-3.5" />
              <span>{cancelling ? 'Cancelling...' : 'Cancel Scan'}</span>
            </button>
          )}
          <button
            onClick={() => {
              fetchScan();
              if (activeTab === 'findings') fetchFindings();
              if (activeTab === 'graph') fetchGraph();
              if (activeTab === 'reports') fetchReports();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-white/5 transition"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-white/10 space-x-1 sm:space-x-4">
        {[
          { key: 'overview', label: 'Pipeline & Score', icon: Shield },
          { key: 'findings', label: `Findings (${scan.findings_count})`, icon: Bug },
          { key: 'graph', label: 'Evidence Graph', icon: Network },
          { key: 'inspector', label: 'Source Inspector', icon: FileCode },
          { key: 'reports', label: 'Reports & Export', icon: FileText },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as any)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs sm:text-sm font-medium border-b-2 transition -mb-px ${
                isActive
                  ? 'border-brand-500 text-brand-400 bg-brand-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: OVERVIEW & PIPELINE */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Score Widget */}
            <div className="glass-card rounded-2xl p-6 border border-white/10 flex flex-col justify-between">
              <div>
                <div className="text-xs uppercase font-bold tracking-wider text-slate-400">Security Score</div>
                <div className="mt-3 flex items-baseline gap-2">
                  <span
                    className={`text-5xl font-black ${
                      (scan.security_score ?? 100) >= 80
                        ? 'text-emerald-400'
                        : (scan.security_score ?? 100) >= 50
                        ? 'text-yellow-400'
                        : 'text-red-400'
                    }`}
                  >
                    {scan.security_score ?? '--'}
                  </span>
                  <span className="text-slate-500 text-lg">/100</span>
                </div>
                <div className="text-xs text-slate-400 mt-2">
                  Deterministic algorithm <code className="text-cyan-400">scoring_v1</code> (Base 100 - deductions)
                </div>
              </div>
              <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between text-xs text-slate-400">
                <span>Total Findings:</span>
                <span className="font-semibold text-white">{scan.findings_count}</span>
              </div>
            </div>

            {/* Pipeline Stage Tracker */}
            <div className="md:col-span-2 glass-card rounded-2xl p-6 border border-white/10 space-y-4">
              <div className="flex items-center justify-between">
                <div className="text-xs uppercase font-bold tracking-wider text-slate-400">Execution Stages</div>
                <span className="text-xs text-slate-400">{scan.stages.length} events logged</span>
              </div>

              <div className="space-y-3">
                {scan.stages.map((stg) => (
                  <div
                    key={stg.id}
                    className="flex items-start gap-3 p-3 rounded-xl bg-slate-950/60 border border-white/5 text-xs"
                  >
                    {stg.status === 'completed' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    ) : stg.status === 'started' ? (
                      <Clock className="w-4 h-4 text-blue-400 shrink-0 mt-0.5 animate-spin" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-200 capitalize">
                          {stg.stage.replace('_', ' ')}
                        </span>
                        {stg.duration_ms && (
                          <span className="text-[10px] font-mono text-cyan-400">{stg.duration_ms}ms</span>
                        )}
                      </div>
                      {stg.message && <p className="text-slate-400 mt-1">{stg.message}</p>}
                    </div>
                  </div>
                ))}
                {scan.stages.length === 0 && (
                  <div className="text-center py-6 text-slate-500 text-xs">Waiting for worker stage pulse...</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: FINDINGS EXPLORATION & TRIAGE */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="glass-card rounded-xl p-4 border border-white/10 flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center bg-slate-950/80 rounded-lg p-1 border border-white/5 text-xs">
                {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-3 py-1 rounded-md capitalize font-medium transition ${
                      severityFilter === sev ? 'bg-brand-500 text-white' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              <div className="flex items-center bg-slate-950/80 rounded-lg p-1 border border-white/5 text-xs">
                {['all', 'open', 'confirmed', 'false_positive', 'accepted_risk'].map((st) => (
                  <button
                    key={st}
                    onClick={() => setStatusFilter(st)}
                    className={`px-3 py-1 rounded-md capitalize font-medium transition ${
                      statusFilter === st ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {st.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search rule ID, title..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-slate-950 border border-white/10 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand-500"
              />
            </div>
          </div>

          {/* Master-Detail Findings Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Findings List (5 columns) */}
            <div className="lg:col-span-5 space-y-2.5">
              {loadingFindings && (
                <div className="text-center py-12 text-slate-400 text-xs flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-brand-400" />
                  <span>Loading findings...</span>
                </div>
              )}

              {!loadingFindings && findings.length === 0 && (
                <div className="glass-card rounded-2xl p-8 text-center text-slate-400 text-xs">
                  No findings match current filter criteria.
                </div>
              )}

              {findings.map((f) => {
                const isSelected = selectedFinding?.id === f.id;
                return (
                  <div
                    key={f.id}
                    onClick={() => fetchFindingDetail(f.id)}
                    className={`glass-card p-4 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? 'border-brand-500 bg-brand-500/10 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
                        : 'border-white/5 hover:border-white/15'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`badge-${f.severity}`}>{f.severity}</span>
                        <span className="text-[11px] font-mono text-cyan-400">{f.rule_id}</span>
                      </div>
                      <span className="text-[10px] uppercase font-semibold text-slate-400 px-2 py-0.5 rounded bg-slate-900 border border-white/5">
                        {f.review_status.replace('_', ' ')}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-white mt-2 line-clamp-1">{f.title}</div>
                    <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">{f.description}</div>
                  </div>
                );
              })}
            </div>

            {/* Finding Detail Pane (7 columns) */}
            <div className="lg:col-span-7">
              {selectedFinding ? (
                <div className="glass-card rounded-2xl p-6 border border-white/10 space-y-5">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`badge-${selectedFinding.severity}`}>{selectedFinding.severity}</span>
                        <span className="text-xs font-mono text-cyan-400">{selectedFinding.rule_id}</span>
                        <span className="text-xs text-slate-400">&bull;</span>
                        <span className="text-xs text-slate-400">Reachability: {selectedFinding.reachability}</span>
                      </div>
                      <h3 className="text-lg font-bold text-white">{selectedFinding.title}</h3>
                    </div>

                    {/* Triage Status Dropdown */}
                    <div className="flex items-center gap-2">
                      <label className="text-xs text-slate-400">Triage:</label>
                      <select
                        value={selectedFinding.review_status}
                        onChange={(e) => handleUpdateFindingStatus(selectedFinding.id, e.target.value)}
                        className="bg-slate-900 border border-white/15 rounded-lg text-xs text-slate-200 px-2.5 py-1.5 focus:outline-none focus:border-brand-500"
                      >
                        <option value="open">Open</option>
                        <option value="confirmed">Confirmed</option>
                        <option value="false_positive">False Positive</option>
                        <option value="accepted_risk">Accepted Risk</option>
                        <option value="fixed">Fixed</option>
                      </select>
                    </div>
                  </div>

                  <p className="text-xs leading-relaxed text-slate-300">{selectedFinding.description}</p>

                  {/* Impact & Preconditions */}
                  {selectedFinding.impact && (
                    <div className="p-3 rounded-xl bg-slate-950/70 border border-white/5 text-xs">
                      <div className="font-semibold text-red-400 mb-1">Impact Analysis</div>
                      <div className="text-slate-300">{selectedFinding.impact}</div>
                    </div>
                  )}

                  {/* Evidence Excerpt */}
                  {selectedFinding.evidence && selectedFinding.evidence.length > 0 && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs text-slate-400">
                        <span>Code & Manifest Evidence Excerpt</span>
                        <span className="font-mono text-cyan-400">
                          {selectedFinding.evidence[0].location || 'Archive root'}
                        </span>
                      </div>
                      <pre className="p-3 rounded-xl bg-[#030712] border border-white/10 text-cyan-300 font-mono text-xs overflow-x-auto leading-relaxed">
                        {selectedFinding.evidence[0].excerpt}
                      </pre>
                    </div>
                  )}

                  {/* Remediation Guidance */}
                  {selectedFinding.remediation && (
                    <div className="p-3.5 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-xs space-y-1">
                      <div className="font-semibold text-cyan-400 flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5" />
                        <span>Remediation Recommendation</span>
                      </div>
                      <div className="text-cyan-100">{selectedFinding.remediation}</div>
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex items-center gap-3 pt-3 border-t border-white/10">
                    <button
                      onClick={() => handleInspectFinding(selectedFinding)}
                      className="flex items-center gap-2 px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-500 text-white font-medium text-xs transition"
                    >
                      <FileCode className="w-4 h-4" />
                      <span>Inspect Code</span>
                    </button>
                    <button
                      onClick={() => setActiveTab('graph')}
                      className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs transition"
                    >
                      <Network className="w-4 h-4 text-cyan-400" />
                      <span>View in Graph</span>
                    </button>
                  </div>
                </div>
              ) : (
                <div className="glass-card rounded-2xl p-12 text-center text-slate-400 text-xs">
                  Select a finding to inspect detailed reachability, occurrences, and remediation.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: EVIDENCE REACHABILITY GRAPH */}
      {activeTab === 'graph' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <span>Evidence Reachability Graph</span>
              </h2>
              <p className="text-xs text-slate-400">
                Visualizing relationships between APK root, declared permissions, exported components, and findings.
              </p>
            </div>
            <div className="text-xs text-slate-400 font-mono">
              Nodes: {graphNodes.length} &bull; Edges: {graphEdges.length}
            </div>
          </div>

          <EvidenceGraph
            nodes={graphNodes}
            edges={graphEdges}
            onSelectNode={(node) => setSelectedGraphNode(node)}
            selectedNodeKey={selectedGraphNode?.node_key}
          />
        </div>
      )}

      {/* TAB 4: SOURCE & BYTECODE INSPECTOR */}
      {activeTab === 'inspector' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <FileCode className="w-4 h-4 text-brand-400" />
                <span>Monaco APK Bytecode & Manifest Inspector</span>
              </h2>
              <p className="text-xs text-slate-400">
                Inspect extracted files, manifest entries, and highlighted vulnerability line ranges directly in-browser.
              </p>
            </div>
          </div>

          <CodeInspector
            scanId={scan.id}
            initialPath={inspectorFile}
            highlightLineStart={inspectorLineStart}
            highlightLineEnd={inspectorLineEnd}
            title={inspectorTitle}
          />
        </div>
      )}

      {/* TAB 5: REPORTS & EXPORT */}
      {activeTab === 'reports' && (
        <div className="space-y-6">
          <div className="glass-card rounded-2xl p-6 border border-white/10 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-brand-400" />
              <span>Generate Security Intelligence Reports</span>
            </h2>
            <p className="text-xs text-slate-400">
              Export tamper-evident reports certified with Attestation of Authorization records, security score, and remediation steps.
            </p>

            <div className="flex flex-wrap items-center gap-4 pt-2">
              <button
                onClick={() => handleGenerateReport('json')}
                disabled={generatingReport !== null}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs transition border border-white/10 disabled:opacity-50"
              >
                <Download className="w-4 h-4 text-cyan-400" />
                <span>{generatingReport === 'json' ? 'Generating JSON...' : 'Generate JSON Report'}</span>
              </button>

              <button
                onClick={() => handleGenerateReport('pdf')}
                disabled={generatingReport !== null}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-500 text-white font-medium text-xs transition disabled:opacity-50"
              >
                <Download className="w-4 h-4" />
                <span>{generatingReport === 'pdf' ? 'Generating Print/PDF...' : 'Generate Print-Ready HTML/PDF'}</span>
              </button>
            </div>
          </div>

          {/* Generated Reports List */}
          <div className="glass-card rounded-2xl p-6 border border-white/10 space-y-4">
            <h3 className="text-xs uppercase font-bold tracking-wider text-slate-400">Available Report Artifacts</h3>
            <div className="space-y-2">
              {reports.map((rep) => (
                <div
                  key={rep.id}
                  className="flex items-center justify-between p-3.5 rounded-xl bg-slate-950/60 border border-white/5 text-xs"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-brand-500/10 text-brand-400">
                      <FileText className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 font-mono">
                        <span className="font-semibold text-white uppercase">{rep.format} Report</span>
                        <span className="text-slate-500">&bull;</span>
                        <span className="text-cyan-400">{rep.status}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5 font-mono">
                        Generated: {new Date(rep.created_at).toLocaleString()} {rep.size_bytes ? `(${Math.round(rep.size_bytes / 1024)} KB)` : ''}
                      </div>
                    </div>
                  </div>

                  {rep.status === 'ready' && (
                    <a
                      href={`/api/v1/reports/${rep.id}/download`}
                      download
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand-500/10 hover:bg-brand-500/20 text-brand-400 border border-brand-500/30 transition text-xs font-medium"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download</span>
                    </a>
                  )}
                </div>
              ))}
              {reports.length === 0 && (
                <div className="text-center py-6 text-slate-500 text-xs">
                  No reports generated yet. Click a button above to generate a new report.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
