import React, { useState, useEffect } from 'react';
import { 
  Sparkles, 
  X, 
  ShieldAlert, 
  CheckCircle2, 
  HelpCircle, 
  ArrowRight, 
  Code2, 
  Bug, 
  FileText, 
  ExternalLink,
  Flame,
  RefreshCw,
  Cpu,
  Check
} from 'lucide-react';
import { apiRequest } from '../../lib/api';

interface AIInvestigationModalProps {
  scanId: string;
  findingId: string;
  findingTitle: string;
  ruleId: string;
  isOpen: boolean;
  onClose: () => void;
  onInspectSource?: (filePath: string, lineStart?: number, lineEnd?: number) => void;
}

interface AnalysisOutput {
  verdict: 'confirmed' | 'likely_false_positive' | 'needs_human_review';
  confidence: string;
  exploitability_score: string;
  reachability_proof: string;
  attack_scenario: string;
  remediation_diff: string;
  executive_summary: string;
  technical_explanation: string;
  cited_evidence_ids: string[];
}

interface InvestigationResult {
  run_id: string;
  agent: string;
  provider: string;
  model: string;
  status: string;
  iterations: number;
  tool_calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd_micros: number;
  analysis: AnalysisOutput;
  created_at: string;
}

interface StoredAnalysis {
  id: string;
  agent_run_id: string;
  scan_id: string;
  finding_id: string;
  kind: string;
  output: AnalysisOutput;
  cited_evidence_ids: string[];
  created_at: string;
  cited_evidence?: Array<{
    id: string;
    location: string | null;
    line_start: number | null;
    line_end: number | null;
    excerpt: string;
  }>;
}

export const AIInvestigationModal: React.FC<AIInvestigationModalProps> = ({
  scanId,
  findingId,
  findingTitle,
  ruleId,
  isOpen,
  onClose,
  onInspectSource,
}) => {
  const [selectedAgent, setSelectedAgent] = useState<'validation_analyst' | 're_analyst' | 'remediation_advisor'>('validation_analyst');
  const [running, setRunning] = useState(false);
  const [activeAnalysis, setActiveAnalysis] = useState<StoredAnalysis | null>(null);
  const [pastAnalyses, setPastAnalyses] = useState<StoredAnalysis[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const fetchAnalyses = () => {
    if (!scanId || !findingId) return;
    setLoadingHistory(true);
    apiRequest<{ analyses: StoredAnalysis[] }>(`/scans/${scanId}/findings/${findingId}/analyses`, { method: 'GET' })
      .then((res) => {
        setPastAnalyses(res.analyses || []);
        if (res.analyses?.length > 0 && !activeAnalysis) {
          fetchAnalysisDetail(res.analyses[0].id);
        }
      })
      .catch((err) => console.error(err))
      .finally(() => setLoadingHistory(false));
  };

  const fetchAnalysisDetail = (analysisId: string) => {
    apiRequest<{ analysis: StoredAnalysis }>(`/analyses/${analysisId}`, { method: 'GET' })
      .then((res) => setActiveAnalysis(res.analysis))
      .catch((err) => console.error(err));
  };

  useEffect(() => {
    if (isOpen) {
      fetchAnalyses();
    }
  }, [isOpen, scanId, findingId]);

  const handleRunInvestigation = async () => {
    setRunning(true);
    try {
      const res = await apiRequest<{ investigation: InvestigationResult }>(
        `/scans/${scanId}/findings/${findingId}/analyses`,
        {
          method: 'POST',
          body: JSON.stringify({ agent: selectedAgent }),
        }
      );
      // Refresh past analyses
      fetchAnalyses();
      // Set active analysis immediately
      setActiveAnalysis({
        id: res.investigation.run_id,
        agent_run_id: res.investigation.run_id,
        scan_id: scanId,
        finding_id: findingId,
        kind: res.investigation.agent,
        output: res.investigation.analysis,
        cited_evidence_ids: res.investigation.analysis.cited_evidence_ids || [],
        created_at: res.investigation.created_at,
      });
    } catch (err: any) {
      alert(err.message || 'AI Investigation failed');
    } finally {
      setRunning(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-4xl max-h-[90vh] glass-panel bg-slate-950/95 border border-white/10 rounded-2xl flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-brand-500/20 to-purple-500/20 text-brand-400 border border-brand-500/30">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-white">AI Security Investigation Agent</span>
                <span className="text-xs font-mono text-cyan-400 font-semibold px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/30">
                  {ruleId}
                </span>
              </div>
              <div className="text-xs text-slate-400 truncate max-w-xl">{findingTitle}</div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Controls: Persona Selection & Trigger */}
          <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/40 border border-white/5">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-medium">Agent Persona:</span>
              <div className="flex bg-slate-950 rounded-lg p-1 border border-white/5 text-xs">
                {[
                  { id: 'validation_analyst', label: 'Validation Analyst' },
                  { id: 're_analyst', label: 'RE Analyst' },
                  { id: 'remediation_advisor', label: 'Remediation Advisor' },
                ].map((a) => (
                  <button
                    key={a.id}
                    onClick={() => setSelectedAgent(a.id as any)}
                    className={`px-3 py-1.5 rounded-md font-medium transition ${
                      selectedAgent === a.id ? 'bg-brand-500 text-white' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {a.label}
                  </button>
                ))}
              </div>
            </div>

            <button
              onClick={handleRunInvestigation}
              disabled={running}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-brand-600 to-cyan-500 hover:from-brand-500 hover:to-cyan-400 text-white font-medium text-xs transition shadow-[0_0_15px_rgba(6,182,212,0.25)] disabled:opacity-50"
            >
              {running ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Agent Executing Tool Calls...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>Run Autonomous Investigation</span>
                </>
              )}
            </button>
          </div>

          {/* Past Runs Selector */}
          {pastAnalyses.length > 0 && (
            <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
              <span className="text-slate-500 shrink-0">Analysis Runs:</span>
              {pastAnalyses.map((an, idx) => (
                <button
                  key={an.id}
                  onClick={() => fetchAnalysisDetail(an.id)}
                  className={`px-3 py-1 rounded-lg border font-mono shrink-0 transition ${
                    activeAnalysis?.id === an.id
                      ? 'bg-brand-500/20 border-brand-500 text-brand-300'
                      : 'bg-slate-900 border-white/5 text-slate-400 hover:text-white'
                  }`}
                >
                  Run #{idx + 1} ({an.kind})
                </button>
              ))}
            </div>
          )}

          {/* Investigation Result Display */}
          {activeAnalysis ? (
            <div className="space-y-5">
              {/* Verdict & Metrics Bar */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl glass-card border border-white/10">
                  <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Verification Verdict</div>
                  <div className="flex items-center gap-2 mt-2">
                    {activeAnalysis.output.verdict === 'confirmed' ? (
                      <>
                        <ShieldAlert className="w-5 h-5 text-red-400" />
                        <span className="text-base font-bold text-red-400 uppercase">Confirmed True Positive</span>
                      </>
                    ) : activeAnalysis.output.verdict === 'likely_false_positive' ? (
                      <>
                        <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                        <span className="text-base font-bold text-emerald-400 uppercase">Likely False Positive</span>
                      </>
                    ) : (
                      <>
                        <HelpCircle className="w-5 h-5 text-yellow-400" />
                        <span className="text-base font-bold text-yellow-400 uppercase">Needs Human Review</span>
                      </>
                    )}
                  </div>
                </div>

                <div className="p-4 rounded-xl glass-card border border-white/10">
                  <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Exploitability Score</div>
                  <div className="flex items-center gap-2 mt-2">
                    <Flame className="w-5 h-5 text-orange-400" />
                    <span className="text-base font-bold text-white capitalize">
                      {activeAnalysis.output.exploitability_score || 'High'}
                    </span>
                    <span className="text-xs text-slate-400">({activeAnalysis.output.confidence} confidence)</span>
                  </div>
                </div>

                <div className="p-4 rounded-xl glass-card border border-white/10">
                  <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Evidence Citations</div>
                  <div className="flex items-center gap-2 mt-2">
                    <Check className="w-5 h-5 text-cyan-400" />
                    <span className="text-base font-bold text-white">
                      {activeAnalysis.cited_evidence_ids?.length || 0} Grounded Items
                    </span>
                  </div>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-white/5 space-y-2">
                <div className="text-xs font-bold text-white flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <span>Executive Assessment</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeAnalysis.output.executive_summary}
                </p>
              </div>

              {/* Reachability Proof */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-white/5 space-y-2">
                <div className="text-xs font-bold text-white flex items-center gap-2">
                  <ArrowRight className="w-4 h-4 text-orange-400" />
                  <span>Reachability Analysis & Attack Path</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeAnalysis.output.reachability_proof}
                </p>
              </div>

              {/* Attack Scenario Walkthrough */}
              {activeAnalysis.output.attack_scenario && (
                <div className="space-y-2">
                  <div className="text-xs font-bold text-white flex items-center gap-2">
                    <Bug className="w-4 h-4 text-red-400" />
                    <span>Step-by-Step Exploitation Walkthrough</span>
                  </div>
                  <pre className="p-4 rounded-xl bg-[#030712] border border-white/10 text-slate-300 font-mono text-xs whitespace-pre-wrap leading-relaxed">
                    {activeAnalysis.output.attack_scenario}
                  </pre>
                </div>
              )}

              {/* Concrete Code Remediation Diff */}
              {activeAnalysis.output.remediation_diff && (
                <div className="space-y-2">
                  <div className="text-xs font-bold text-cyan-400 flex items-center gap-2">
                    <Code2 className="w-4 h-4" />
                    <span>Concrete Code Patch / Remediation Diff</span>
                  </div>
                  <pre className="p-4 rounded-xl bg-[#030712] border border-cyan-500/20 text-cyan-300 font-mono text-xs whitespace-pre-wrap leading-relaxed">
                    {activeAnalysis.output.remediation_diff}
                  </pre>
                </div>
              )}

              {/* Cited Evidence Chips */}
              {activeAnalysis.cited_evidence && activeAnalysis.cited_evidence.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-white/10">
                  <div className="text-xs font-bold text-slate-400 flex items-center gap-2">
                    <FileText className="w-4 h-4 text-brand-400" />
                    <span>Cited Evidence Excerpts</span>
                  </div>
                  <div className="space-y-2">
                    {activeAnalysis.cited_evidence.map((ev) => (
                      <div key={ev.id} className="p-3 rounded-lg bg-slate-950/80 border border-white/5 text-xs">
                        <div className="flex items-center justify-between text-slate-400 font-mono text-[11px] mb-1">
                          <span>{ev.location || 'APK Root'}</span>
                          {onInspectSource && ev.location && (
                            <button
                              onClick={() => {
                                onInspectSource(ev.location!, ev.line_start || undefined, ev.line_end || undefined);
                                onClose();
                              }}
                              className="text-brand-400 hover:text-brand-300 flex items-center gap-1 font-sans"
                            >
                              <span>Inspect in Monaco</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          )}
                        </div>
                        <pre className="text-slate-300 font-mono text-[11px] overflow-x-auto">{ev.excerpt}</pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-16 space-y-3">
              <div className="inline-flex p-3 rounded-2xl bg-brand-500/10 text-brand-400 border border-brand-500/20">
                <Sparkles className="w-8 h-8 animate-pulse" />
              </div>
              <h4 className="text-sm font-bold text-white">Autonomous Agent Ready</h4>
              <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
                Click &ldquo;Run Autonomous Investigation&rdquo; above to dispatch the AI agent. The agent will execute tool calls to query static evidence, verify reachability, and produce an evidence-backed verification verdict.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
