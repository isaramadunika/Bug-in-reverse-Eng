import React, { useState, useEffect, useRef } from 'react';
import Editor, { OnMount } from '@monaco-editor/react';
import { FileCode, Copy, Check, Folder, Search, AlertCircle, RefreshCw } from 'lucide-react';
import { apiRequest } from '../../lib/api';

interface SourceFileResponse {
  path: string;
  content: string;
  size_bytes: number;
  is_truncated: boolean;
  language: string;
  archive_files?: string[];
}

interface CodeInspectorProps {
  scanId: string;
  initialPath?: string;
  highlightLineStart?: number;
  highlightLineEnd?: number;
  title?: string;
}

export const CodeInspector: React.FC<CodeInspectorProps> = ({
  scanId,
  initialPath = 'AndroidManifest.xml',
  highlightLineStart,
  highlightLineEnd,
  title,
}) => {
  const [currentPath, setCurrentPath] = useState(initialPath);
  const [fileData, setFileData] = useState<SourceFileResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');
  const [showFilePicker, setShowFilePicker] = useState(false);
  const editorRef = useRef<any>(null);
  const decorationsRef = useRef<string[]>([]);

  const fetchSource = (filePath: string) => {
    setLoading(true);
    apiRequest<SourceFileResponse>(`/scans/${scanId}/source-file?path=${encodeURIComponent(filePath)}`, {
      method: 'GET',
    })
      .then((res) => {
        setFileData(res);
        setCurrentPath(res.path);
      })
      .catch((err) => console.error('Failed to load source file:', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (initialPath) {
      fetchSource(initialPath);
    }
  }, [scanId, initialPath]);

  // Apply line highlighting decoration when editor is mounted or lines change
  const applyHighlight = (editor: any, start?: number, end?: number) => {
    if (!editor || !start) return;
    const targetEnd = end || start;

    // Reveal and scroll line in center
    editor.revealLineInCenter(start);

    // Add highlighted range decoration
    const newDecorations = [
      {
        range: {
          startLineNumber: start,
          startColumn: 1,
          endLineNumber: targetEnd,
          endColumn: 1000,
        },
        options: {
          isWholeLine: true,
          className: 'bg-red-500/20 border-l-4 border-red-500',
          glyphMarginClassName: 'bg-red-500',
        },
      },
    ];

    decorationsRef.current = editor.deltaDecorations(decorationsRef.current, newDecorations);
  };

  const handleEditorMount: OnMount = (editor) => {
    editorRef.current = editor;
    if (highlightLineStart) {
      applyHighlight(editor, highlightLineStart, highlightLineEnd);
    }
  };

  useEffect(() => {
    if (editorRef.current && highlightLineStart) {
      applyHighlight(editorRef.current, highlightLineStart, highlightLineEnd);
    }
  }, [highlightLineStart, highlightLineEnd, fileData]);

  const handleCopy = () => {
    if (!fileData?.content) return;
    navigator.clipboard.writeText(fileData.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredArchiveFiles = (fileData?.archive_files || []).filter((f) =>
    f.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div className="flex flex-col h-[620px] rounded-2xl glass-panel border border-white/10 overflow-hidden shadow-2xl">
      {/* Inspector Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-950/80 border-b border-white/10 gap-3">
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg bg-brand-500/10 text-brand-400">
            <FileCode className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-medium text-slate-200">{currentPath}</span>
              {fileData?.language && (
                <span className="text-[10px] font-mono uppercase bg-slate-800 text-cyan-400 px-2 py-0.5 rounded border border-white/5">
                  {fileData.language}
                </span>
              )}
              {fileData?.is_truncated && (
                <span className="text-[10px] bg-yellow-500/10 text-yellow-400 px-2 py-0.5 rounded border border-yellow-500/30">
                  Truncated to 2MB
                </span>
              )}
            </div>
            {title && <div className="text-[11px] text-slate-400 mt-0.5">{title}</div>}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* File Picker Toggle */}
          <button
            onClick={() => setShowFilePicker(!showFilePicker)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-white/5 transition"
          >
            <Folder className="w-3.5 h-3.5 text-cyan-400" />
            <span>Files ({fileData?.archive_files?.length || 0})</span>
          </button>

          {/* Copy Button */}
          <button
            onClick={handleCopy}
            disabled={!fileData?.content}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-white/5 transition disabled:opacity-50"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-slate-400" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Main Workspace Area: Drawer for Files & Monaco Editor */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Archive File Picker Drawer */}
        {showFilePicker && (
          <div className="w-72 bg-slate-950/95 border-r border-white/10 flex flex-col z-10 shrink-0">
            <div className="p-3 border-b border-white/10">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter archive entries..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="w-full bg-slate-900 border border-white/10 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-brand-500"
                />
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-0.5 font-mono text-xs">
              {filteredArchiveFiles.map((file) => {
                const isActive = file === currentPath;
                return (
                  <button
                    key={file}
                    onClick={() => {
                      fetchSource(file);
                      setShowFilePicker(false);
                    }}
                    className={`w-full text-left px-2.5 py-1.5 rounded-md truncate transition flex items-center gap-2 ${
                      isActive
                        ? 'bg-brand-500/20 text-brand-300 border border-brand-500/30'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                    }`}
                  >
                    <FileCode className="w-3.5 h-3.5 shrink-0 opacity-70" />
                    <span className="truncate">{file}</span>
                  </button>
                );
              })}
              {filteredArchiveFiles.length === 0 && (
                <div className="p-4 text-center text-xs text-slate-500">No matching files found</div>
              )}
            </div>
          </div>
        )}

        {/* Monaco Editor Container */}
        <div className="flex-1 h-full bg-[#030712] relative">
          {loading && (
            <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm z-20 flex items-center justify-center gap-2 text-xs text-brand-400">
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>Loading source from APK archive...</span>
            </div>
          )}

          <Editor
            height="100%"
            theme="vs-dark"
            language={fileData?.language || 'plaintext'}
            value={fileData?.content || '// Loading or file is empty...'}
            onMount={handleEditorMount}
            options={{
              readOnly: true,
              minimap: { enabled: true },
              fontSize: 13,
              fontFamily: "'JetBrains Mono', 'Fira Code', Menlo, Monaco, Consolas, monospace",
              lineNumbers: 'on',
              scrollBeyondLastLine: false,
              automaticLayout: true,
              wordWrap: 'on',
              renderWhitespace: 'selection',
            }}
          />
        </div>
      </div>
    </div>
  );
};
