import React, { useMemo } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  BackgroundVariant,
  Node,
  Edge,
  MarkerType,
  Handle,
  Position,
} from '@xyflow/react';
import { Shield, Smartphone, AlertTriangle, Key, Layers, Bug, ExternalLink } from 'lucide-react';

export interface EvidenceNodeData {
  id: string;
  scan_id: string;
  node_key: string;
  node_type: string;
  label: string;
  severity: string | null;
  properties: Record<string, any>;
  evidence_id?: string | null;
}

export interface EvidenceEdgeData {
  id: string;
  scan_id: string;
  source_id: string;
  target_id: string;
  edge_type: string;
  relation_status: string;
  provenance: Record<string, any>;
}

interface EvidenceGraphProps {
  nodes: EvidenceNodeData[];
  edges: EvidenceEdgeData[];
  onSelectNode?: (node: EvidenceNodeData) => void;
  selectedNodeKey?: string;
}

// Custom Node for Root APK
const ApkNode = ({ data, selected }: { data: any; selected?: boolean }) => (
  <div
    className={`px-4 py-3 rounded-xl glass-panel border transition-all duration-200 cursor-pointer ${
      selected
        ? 'border-brand-400 shadow-[0_0_20px_rgba(6,182,212,0.4)] ring-2 ring-brand-400'
        : 'border-cyan-500/40 hover:border-cyan-400'
    }`}
    style={{ minWidth: 200 }}
  >
    <Handle type="source" position={Position.Bottom} className="w-2.5 h-2.5 !bg-brand-400" />
    <div className="flex items-center gap-2.5 mb-1.5">
      <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400">
        <Smartphone className="w-4 h-4" />
      </div>
      <div>
        <div className="text-[10px] uppercase font-bold tracking-wider text-cyan-400">APK Package</div>
        <div className="text-xs font-semibold text-white truncate max-w-[150px]">{data.label}</div>
      </div>
    </div>
    {data.properties?.version_name && (
      <div className="text-[10px] text-slate-400">v{data.properties.version_name} (API {data.properties.min_sdk || '21'}+)</div>
    )}
  </div>
);

// Custom Node for Entry Points & Components
const ComponentNode = ({ data, selected }: { data: any; selected?: boolean }) => {
  const isEntryPoint = data.node_type === 'entry_point';
  return (
    <div
      className={`px-3.5 py-2.5 rounded-xl glass-panel border transition-all duration-200 cursor-pointer ${
        selected
          ? 'border-brand-400 ring-2 ring-brand-400'
          : isEntryPoint
          ? 'border-orange-500/40 hover:border-orange-400 shadow-[0_0_12px_rgba(249,115,22,0.15)]'
          : 'border-slate-700/60 hover:border-slate-500'
      }`}
      style={{ minWidth: 170 }}
    >
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-slate-400" />
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-slate-400" />
      <div className="flex items-center gap-2">
        <div className={`p-1.5 rounded-lg ${isEntryPoint ? 'bg-orange-500/10 text-orange-400' : 'bg-slate-800 text-slate-300'}`}>
          {isEntryPoint ? <ExternalLink className="w-3.5 h-3.5" /> : <Layers className="w-3.5 h-3.5" />}
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded ${isEntryPoint ? 'bg-orange-500/20 text-orange-400' : 'bg-slate-800 text-slate-400'}`}>
              {isEntryPoint ? 'Entry Point' : 'Component'}
            </span>
          </div>
          <div className="text-xs font-medium text-slate-200 truncate max-w-[140px] mt-0.5">{data.label}</div>
        </div>
      </div>
    </div>
  );
};

// Custom Node for Declared Permissions
const PermissionNode = ({ data, selected }: { data: any; selected?: boolean }) => (
  <div
    className={`px-3 py-2 rounded-lg glass-panel border transition-all duration-200 cursor-pointer ${
      selected ? 'border-emerald-400 ring-1 ring-emerald-400' : 'border-emerald-500/30 hover:border-emerald-400'
    }`}
    style={{ minWidth: 140 }}
  >
    <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-emerald-400" />
    <div className="flex items-center gap-2">
      <div className="p-1 rounded bg-emerald-500/10 text-emerald-400">
        <Key className="w-3 h-3" />
      </div>
      <div>
        <div className="text-[9px] uppercase font-bold text-emerald-400">Permission</div>
        <div className="text-[11px] font-medium text-slate-200 truncate max-w-[120px]">{data.label}</div>
      </div>
    </div>
  </div>
);

// Custom Node for Security Findings
const FindingNode = ({ data, selected }: { data: any; selected?: boolean }) => {
  const sev = data.severity?.toLowerCase() || 'medium';
  const colorMap: Record<string, { border: string; bg: string; text: string; glow: string }> = {
    critical: { border: 'border-red-500/70', bg: 'bg-red-500/10', text: 'text-red-400', glow: 'shadow-[0_0_15px_rgba(239,68,68,0.3)]' },
    high: { border: 'border-orange-500/70', bg: 'bg-orange-500/10', text: 'text-orange-400', glow: 'shadow-[0_0_12px_rgba(249,115,22,0.25)]' },
    medium: { border: 'border-yellow-500/70', bg: 'bg-yellow-500/10', text: 'text-yellow-400', glow: 'shadow-[0_0_10px_rgba(234,179,8,0.2)]' },
    low: { border: 'border-blue-500/70', bg: 'bg-blue-500/10', text: 'text-blue-400', glow: 'shadow-[0_0_8px_rgba(59,130,246,0.15)]' },
    info: { border: 'border-slate-500/70', bg: 'bg-slate-500/10', text: 'text-slate-400', glow: '' },
  };
  const theme = colorMap[sev] || colorMap.medium;

  return (
    <div
      className={`px-3.5 py-2.5 rounded-xl glass-panel border transition-all duration-200 cursor-pointer ${theme.border} ${theme.glow} ${
        selected ? 'ring-2 ring-white scale-105' : 'hover:scale-[1.02]'
      }`}
      style={{ minWidth: 190 }}
    >
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-slate-300" />
      <div className="flex items-start gap-2">
        <div className={`p-1.5 rounded-lg ${theme.bg} ${theme.text} mt-0.5`}>
          <Bug className="w-3.5 h-3.5" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className={`text-[9px] uppercase font-bold px-1.5 py-0.2 rounded ${theme.bg} ${theme.text}`}>
              {sev}
            </span>
            {data.properties?.rule_id && (
              <span className="text-[9px] text-slate-400 font-mono">{data.properties.rule_id}</span>
            )}
          </div>
          <div className="text-xs font-semibold text-white line-clamp-2 mt-1 leading-snug">{data.label}</div>
        </div>
      </div>
    </div>
  );
};

const nodeTypes = {
  apk: ApkNode,
  component: ComponentNode,
  entry_point: ComponentNode,
  permission: PermissionNode,
  finding: FindingNode,
};

export const EvidenceGraph: React.FC<EvidenceGraphProps> = ({
  nodes: rawNodes,
  edges: rawEdges,
  onSelectNode,
  selectedNodeKey,
}) => {
  // Map raw nodes into React Flow nodes with tiered positions
  const { flowNodes, flowEdges } = useMemo(() => {
    // ID to node object map
    const idMap: Record<string, EvidenceNodeData> = {};
    rawNodes.forEach((n) => {
      idMap[n.id] = n;
    });

    // Group nodes by type for tiered layout
    const apkNodes: EvidenceNodeData[] = [];
    const permNodes: EvidenceNodeData[] = [];
    const compNodes: EvidenceNodeData[] = [];
    const findingNodes: EvidenceNodeData[] = [];

    rawNodes.forEach((n) => {
      if (n.node_type === 'apk') apkNodes.push(n);
      else if (n.node_type === 'permission') permNodes.push(n);
      else if (n.node_type === 'finding') findingNodes.push(n);
      else compNodes.push(n);
    });

    const flowNodes: Node[] = [];

    // Layer 1: Root APK at (400, 40)
    apkNodes.forEach((n, idx) => {
      flowNodes.push({
        id: n.id,
        type: 'apk',
        position: { x: 420 + idx * 240, y: 30 },
        data: { ...n },
        selected: n.node_key === selectedNodeKey,
      });
    });

    // Layer 2: Permissions on the left column
    permNodes.forEach((n, idx) => {
      flowNodes.push({
        id: n.id,
        type: 'permission',
        position: { x: 40 + (idx % 2) * 160, y: 160 + Math.floor(idx / 2) * 70 },
        data: { ...n },
        selected: n.node_key === selectedNodeKey,
      });
    });

    // Layer 2: Components & Entry points in the center
    compNodes.forEach((n, idx) => {
      flowNodes.push({
        id: n.id,
        type: n.node_type,
        position: { x: 380 + (idx % 3) * 200, y: 170 + Math.floor(idx / 3) * 85 },
        data: { ...n },
        selected: n.node_key === selectedNodeKey,
      });
    });

    // Layer 3: Findings at the bottom
    findingNodes.forEach((n, idx) => {
      flowNodes.push({
        id: n.id,
        type: 'finding',
        position: { x: 200 + (idx % 4) * 220, y: 380 + Math.floor(idx / 4) * 100 },
        data: { ...n },
        selected: n.node_key === selectedNodeKey,
      });
    });

    // Edges
    const flowEdges: Edge[] = rawEdges.map((e) => {
      let stroke = '#64748b';
      let animated = false;

      if (e.edge_type === 'ASSOCIATED_WITH') {
        stroke = '#f87171'; // finding association
        animated = true;
      } else if (e.edge_type === 'REQUIRES_PERMISSION') {
        stroke = '#10b981';
      } else if (e.edge_type === 'DECLARES') {
        stroke = '#06b6d4';
      }

      return {
        id: e.id,
        source: e.source_id,
        target: e.target_id,
        animated,
        style: { stroke, strokeWidth: 1.5, opacity: 0.75 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: 14,
          height: 14,
          color: stroke,
        },
      };
    });

    return { flowNodes, flowEdges };
  }, [rawNodes, rawEdges, selectedNodeKey]);

  return (
    <div className="w-full h-[620px] rounded-2xl glass-panel border border-white/10 overflow-hidden relative">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, node) => {
          if (onSelectNode) {
            onSelectNode(node.data as unknown as EvidenceNodeData);
          }
        }}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.2}
        maxZoom={2.5}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="rgba(255, 255, 255, 0.08)" />
        <Controls className="!bg-slate-900/90 !border !border-slate-800 !rounded-xl !text-slate-300" />
        <MiniMap
          nodeStrokeWidth={3}
          zoomable
          pannable
          className="!bg-slate-950/80 !border !border-slate-800 !rounded-xl"
          maskColor="rgba(15, 23, 42, 0.7)"
        />
      </ReactFlow>

      {/* Legend Badge Overlay */}
      <div className="absolute top-4 right-4 glass-card px-3.5 py-2 rounded-xl text-[11px] text-slate-300 flex items-center gap-3 border border-white/10 pointer-events-none">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyan-400" /> APK</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-orange-400" /> Entry Point</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400" /> Permission</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-400" /> Finding</span>
      </div>
    </div>
  );
};
