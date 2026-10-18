import React, { useState } from 'react';
import { 
  Sparkles, 
  Send, 
  Cpu, 
  User, 
  Bug, 
  CheckSquare, 
  HelpCircle, 
  RefreshCw,
  ExternalLink 
} from 'lucide-react';
import { apiRequest } from '../../lib/api';

interface CopilotAnswerResponse {
  question: string;
  answer: string;
  cited_finding_ids?: string[];
  suggested_fixes?: string[];
  model: string;
  tokens_used: number;
}

interface Message {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  citedFindingIds?: string[];
  suggestedFixes?: string[];
  timestamp: Date;
}

interface SecurityCopilotProps {
  scanId: string;
  onSelectFinding?: (findingId: string) => void;
}

export const SecurityCopilot: React.FC<SecurityCopilotProps> = ({ scanId, onSelectFinding }) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      text: "Hello! I am your **ReverseBug Security Copilot**, grounded in the static analysis evidence, component reachability graph, and deterministic security score for this scan.\n\nAsk me anything about potential attack vectors, exploit feasibility, or remediation strategies.",
      timestamp: new Date(),
    },
  ]);
  const [inputQuestion, setInputQuestion] = useState('');
  const [asking, setAsking] = useState(false);

  const quickPrompts = [
    'Summarize top critical risks in this APK',
    'Can external applications hijack AuthActivity?',
    'How do I fix cleartext traffic and debuggable flags?',
    'Generate an executive remediation checklist',
  ];

  const handleSend = async (questionText?: string) => {
    const q = questionText || inputQuestion.trim();
    if (!q || asking) return;

    const userMsg: Message = {
      id: String(Date.now()),
      sender: 'user',
      text: q,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInputQuestion('');
    setAsking(true);

    try {
      const res = await apiRequest<CopilotAnswerResponse>(`/scans/${scanId}/ask`, {
        method: 'POST',
        body: JSON.stringify({ question: q }),
      });

      const assistantMsg: Message = {
        id: String(Date.now() + 1),
        sender: 'assistant',
        text: res.answer,
        citedFindingIds: res.cited_finding_ids,
        suggestedFixes: res.suggested_fixes,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: Message = {
        id: String(Date.now() + 1),
        sender: 'assistant',
        text: `Error processing request: ${err.message || 'Failed to reach AI copilot.'}`,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setAsking(false);
    }
  };

  return (
    <div className="flex flex-col h-[640px] rounded-2xl glass-panel border border-white/10 overflow-hidden shadow-2xl">
      {/* Copilot Header */}
      <div className="flex items-center justify-between px-6 py-3.5 bg-slate-950/80 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-gradient-to-br from-brand-500/20 to-purple-500/20 text-brand-400 border border-brand-500/30">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-white flex items-center gap-2">
              <span>Security Intelligence Copilot</span>
              <span className="text-[10px] font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/20">
                Evidence-Grounded
              </span>
            </div>
            <div className="text-[11px] text-slate-400">Scan ID: {scanId.slice(0, 8)}...</div>
          </div>
        </div>
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {messages.map((m) => (
          <div
            key={m.id}
            className={`flex items-start gap-3 ${m.sender === 'user' ? 'flex-row-reverse' : ''}`}
          >
            <div
              className={`p-2 rounded-xl shrink-0 ${
                m.sender === 'user'
                  ? 'bg-brand-600 text-white'
                  : 'bg-slate-900 border border-white/10 text-cyan-400'
              }`}
            >
              {m.sender === 'user' ? <User className="w-4 h-4" /> : <Cpu className="w-4 h-4" />}
            </div>

            <div
              className={`max-w-2xl rounded-2xl p-4 text-xs leading-relaxed space-y-3 ${
                m.sender === 'user'
                  ? 'bg-brand-600/90 text-white border border-brand-500/30'
                  : 'glass-card border border-white/10 text-slate-200'
              }`}
            >
              <div className="whitespace-pre-wrap">{m.text}</div>

              {/* Cited Findings Chips */}
              {m.citedFindingIds && m.citedFindingIds.length > 0 && (
                <div className="pt-2 border-t border-white/10 space-y-1.5">
                  <div className="text-[10px] font-bold text-slate-400 flex items-center gap-1.5 uppercase tracking-wider">
                    <Bug className="w-3 h-3 text-red-400" />
                    <span>Cited Findings ({m.citedFindingIds.length}):</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {m.citedFindingIds.map((fId) => (
                      <button
                        key={fId}
                        onClick={() => onSelectFinding && onSelectFinding(fId)}
                        className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 border border-white/10 text-[10px] font-mono text-cyan-300 hover:text-white hover:border-cyan-400 transition"
                      >
                        <span>{fId.slice(0, 8)}...</span>
                        <ExternalLink className="w-2.5 h-2.5" />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Suggested Fixes Checklist */}
              {m.suggestedFixes && m.suggestedFixes.length > 0 && (
                <div className="pt-2 border-t border-white/10 space-y-1.5">
                  <div className="text-[10px] font-bold text-emerald-400 flex items-center gap-1.5 uppercase tracking-wider">
                    <CheckSquare className="w-3 h-3" />
                    <span>Actionable Recommendations:</span>
                  </div>
                  <ul className="space-y-1 text-slate-300">
                    {m.suggestedFixes.map((fix, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-emerald-400 font-bold">&bull;</span>
                        <span>{fix}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        ))}

        {asking && (
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-slate-900 text-cyan-400 border border-white/10 shrink-0">
              <RefreshCw className="w-4 h-4 animate-spin" />
            </div>
            <div className="glass-card px-4 py-2.5 rounded-2xl text-xs text-slate-400 flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span>Analyzing scan graph and synthesizing answer...</span>
            </div>
          </div>
        )}
      </div>

      {/* Quick Prompts Bar */}
      <div className="px-6 py-2 bg-slate-950/60 border-t border-white/5 flex items-center gap-2 overflow-x-auto text-xs">
        <span className="text-slate-500 shrink-0 text-[11px]">Suggestions:</span>
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            disabled={asking}
            onClick={() => handleSend(p)}
            className="px-2.5 py-1 rounded-full bg-slate-900/80 hover:bg-slate-800 text-slate-300 border border-white/5 whitespace-nowrap text-[11px] transition disabled:opacity-50"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input Box */}
      <div className="p-4 bg-slate-950/90 border-t border-white/10 flex items-center gap-3">
        <input
          type="text"
          placeholder="Ask a question about this scan's findings, attack vectors, or remediation..."
          value={inputQuestion}
          onChange={(e) => setInputQuestion(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          disabled={asking}
          className="flex-1 bg-slate-900 border border-white/10 rounded-xl px-4 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 transition"
        />
        <button
          onClick={() => handleSend()}
          disabled={!inputQuestion.trim() || asking}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-500 text-white font-medium text-xs transition disabled:opacity-50 shadow-[0_0_15px_rgba(6,182,212,0.2)]"
        >
          <Send className="w-3.5 h-3.5" />
          <span>Ask</span>
        </button>
      </div>
    </div>
  );
};
