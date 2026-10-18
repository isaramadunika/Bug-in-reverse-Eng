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
  StopCircle
} from 'lucide-react';

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

export const ScanDetail: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [cancelling, setCancelling] = useState(false);

  const fetchScan = () => {
    if (!scanId) return;
    apiRequest<{ scan: ScanData }>(`/scans/${scanId}`, { method: 'GET' })
      .then((res) => setScan(res.scan))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchScan();
    // Auto-poll while running or queued
    const interval = setInterval(() => {
      if (scan?.status === 'queued' || scan?.status === 'running') {
        fetchScan();
      }
    }, 2500);
    return () => clearInterval(interval);
  }, [scanId, scan?.status]);

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
      </div>
    );
  }

  const isRunning = scan.status === 'queued' || scan.status === 'running';

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Breadcrumbs */}
      <div className="flex items-center space-x-2 text-xs text-slate-400">
        <Link to={`/projects/${scan.project_id}`} className="hover:text-white flex items-center space-x-1">
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Project</span>
        </Link>
        <span>/</span>
        <span className="text-white font-medium">Scan {scan.id.slice(0, 8)}</span>
      </div>

      {/* Header Banner */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6 border border-white/10">
        <div className="space-y-3">
          <div className="flex items-center space-x-3">
            <span className="text-xs font-mono uppercase tracking-wider text-brand-400 bg-brand-500/10 px-2.5 py-0.5 rounded border border-brand-500/20">
              {scan.profile_id} Profile
            </span>
            <span className={`text-xs font-mono px-2.5 py-0.5 rounded ${
              scan.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
              scan.status === 'running' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse' :
              scan.status === 'failed' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
              'bg-slate-500/10 text-slate-400 border border-white/10'
            }`}>
              {scan.status.toUpperCase()}
            </span>
          </div>

          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-3">
            <span>{scan.original_filename}</span>
          </h1>

          <div className="flex items-center space-x-4 text-xs text-slate-400 font-mono">
            {scan.package_name && <span>Package: <strong className="text-white">{scan.package_name}</strong></span>}
            <span>Created: {new Date(scan.created_at).toLocaleTimeString()}</span>
          </div>
        </div>

        {/* Score & Controls */}
        <div className="flex items-center space-x-4">
          {scan.security_score !== null ? (
            <div className="glass-card px-6 py-3 rounded-xl text-center border border-white/10">
              <div className={`text-3xl font-mono font-bold ${
                scan.security_score >= 80 ? 'text-emerald-400' :
                scan.security_score >= 60 ? 'text-amber-400' : 'text-rose-400'
              }`}>
                {scan.security_score}
              </div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Security Score</span>
            </div>
          ) : (
            isRunning && (
              <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono bg-cyan-500/10 px-3 py-2 rounded-lg border border-cyan-500/20">
                <RefreshCw className="h-4 w-4 animate-spin" />
                <span>Worker Analyzing...</span>
              </div>
            )
          )}

          {isRunning && (
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="p-2.5 text-rose-400 hover:text-white bg-rose-500/10 hover:bg-rose-500/20 rounded-xl border border-rose-500/30 transition-colors flex items-center space-x-1.5 text-xs font-medium"
              title="Cancel Analysis"
            >
              <StopCircle className="h-4 w-4" />
              <span>{cancelling ? 'Cancelling...' : 'Cancel'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Progress & Stage Events */}
      <div className="glass-card rounded-2xl p-6 sm:p-8 space-y-6 border border-white/10">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
          <Clock className="h-4 w-4 text-brand-400" />
          <span>Execution Stages & Timeline</span>
        </h3>

        <div className="space-y-4">
          {scan.stages && scan.stages.length > 0 ? (
            <div className="divide-y divide-white/5">
              {scan.stages.map((st) => (
                <div key={st.id} className="py-3 flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-3">
                    {st.status === 'completed' ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    ) : st.status === 'started' ? (
                      <RefreshCw className="h-4 w-4 text-cyan-400 animate-spin" />
                    ) : (
                      <XCircle className="h-4 w-4 text-rose-400" />
                    )}
                    <div>
                      <span className="font-bold text-white uppercase font-mono tracking-wider mr-2">
                        {st.stage}
                      </span>
                      <span className="text-slate-400">{st.message || ''}</span>
                    </div>
                  </div>

                  <div className="text-right text-[11px] font-mono text-slate-500">
                    {st.duration_ms !== null && <span>{st.duration_ms}ms • </span>}
                    {new Date(st.created_at).toLocaleTimeString()}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-400">Waiting for worker to claim scan job...</p>
          )}
        </div>
      </div>

      {/* Findings Summary Card */}
      {scan.status === 'completed' && (
        <div className="glass-card rounded-2xl p-6 sm:p-8 space-y-4 border border-white/10">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              <span>Identified Security Findings ({scan.findings_count})</span>
            </h3>
          </div>

          {scan.score_breakdown && (
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2">
              {[
                { label: 'Critical', count: scan.score_breakdown.by_severity?.critical || 0, color: 'text-rose-400 bg-rose-500/10 border-rose-500/20' },
                { label: 'High', count: scan.score_breakdown.by_severity?.high || 0, color: 'text-amber-400 bg-amber-500/10 border-amber-500/20' },
                { label: 'Medium', count: scan.score_breakdown.by_severity?.medium || 0, color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
                { label: 'Low', count: scan.score_breakdown.by_severity?.low || 0, color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
                { label: 'Info', count: scan.score_breakdown.by_severity?.info || 0, color: 'text-slate-400 bg-white/5 border-white/10' },
              ].map((sev) => (
                <div key={sev.label} className={`p-3 rounded-xl border text-center ${sev.color}`}>
                  <span className="text-xl font-mono font-bold block">{sev.count}</span>
                  <span className="text-[10px] uppercase tracking-wider block font-medium">{sev.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
