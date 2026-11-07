import React, { useState, useEffect, useRef } from 'react';

// Entity type badges and colors
const ENTITY_CONFIG = {
  domain: { color: '#6366f1', label: 'Domain', icon: '🌐' },
  ip_address: { color: '#06b6d4', label: 'IP Address', icon: '🖥️' },
  certificate: { color: '#10b981', label: 'Certificate', icon: '🔒' },
  url: { color: '#f59e0b', label: 'URL', icon: '🔗' },
  report: { color: '#f43f5e', label: 'Report', icon: '🚩' },
  nameserver: { color: '#8b5cf6', label: 'Nameserver', icon: '📡' },
  organization: { color: '#ec4899', label: 'Organization', icon: '🏢' },
};

export default function InvestigationGraph({ scanId, targetDomain, onSelectDomain }) {
  const [graphData, setGraphData] = useState({ nodes: [], edges: [], metadata: {} });
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [filterType, setFilterType] = useState('all');
  const [filterEdgeType, setFilterEdgeType] = useState('all');
  const [domainFilter, setDomainFilter] = useState(targetDomain || '');

  // Canvas pan & zoom state
  const [pan, setPan] = useState({ x: 450, y: 300 });
  const [zoom, setZoom] = useState(1);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [nodePositions, setNodePositions] = useState({});

  useEffect(() => {
    fetchGraph();
  }, [scanId, domainFilter]);

  async function fetchGraph() {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (scanId) params.append('scan_id', scanId);
      if (domainFilter) params.append('hostname', domainFilter);
      params.append('max_nodes', '150');

      const res = await fetch(`/api/graph?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to load graph');
      const data = await res.json();
      setGraphData(data);
      initializeLayout(data.nodes || [], data.edges || []);
    } catch (err) {
      console.error('Graph fetch error:', err);
    } finally {
      setLoading(false);
    }
  }

  // Radial / Circle Force Layout Initializer
  function initializeLayout(nodes, edges) {
    const pos = {};
    const centerNode = nodes.find(n => n.type === 'domain') || nodes[0];
    const width = 800;
    const height = 600;

    if (nodes.length === 0) {
      setNodePositions({});
      return;
    }

    // Place center node
    if (centerNode) {
      pos[centerNode.entity_id] = { x: 0, y: 0 };
    }

    const otherNodes = nodes.filter(n => n !== centerNode);
    const radiusStep = 180;
    const total = otherNodes.length;

    otherNodes.forEach((node, i) => {
      // Group by layer/type
      let layer = 1;
      if (node.type === 'url') layer = 0.8;
      else if (node.type === 'ip_address' || node.type === 'certificate') layer = 1.3;
      else if (node.type === 'report') layer = 1.8;

      const angle = (i / Math.max(1, total)) * 2 * Math.PI;
      const r = radiusStep * layer + (i % 2 === 0 ? 30 : -30);
      pos[node.entity_id] = {
        x: Math.cos(angle) * r,
        y: Math.sin(angle) * r,
      };
    });

    setNodePositions(pos);
  }

  // Pan handlers
  function handleMouseDown(e) {
    if (e.target.tagName === 'circle' || e.target.tagName === 'text') return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  }

  function handleMouseMove(e) {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  }

  function handleMouseUp() {
    setIsDragging(false);
  }

  function handleWheel(e) {
    e.preventDefault();
    const newZoom = Math.min(Math.max(0.3, zoom - e.deltaY * 0.001), 2.5);
    setZoom(newZoom);
  }

  // Filtering
  const filteredNodes = graphData.nodes.filter(n => {
    if (filterType === 'all') return true;
    return n.type === filterType;
  });

  const visibleNodeIds = new Set(filteredNodes.map(n => n.entity_id));

  const filteredEdges = graphData.edges.filter(e => {
    if (!visibleNodeIds.has(e.source_entity_id) || !visibleNodeIds.has(e.target_entity_id)) return false;
    if (filterEdgeType !== 'all') return e.type === filterEdgeType;
    return true;
  });

  // Extract unique edge types for filter
  const edgeTypes = Array.from(new Set(graphData.edges.map(e => e.type)));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)', gap: 16 }}>
      {/* Top Filter Bar */}
      <div style={{
        background: '#151d30',
        padding: '12px 20px',
        borderRadius: 12,
        border: '1px solid #23304c',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 13, color: '#94a3b8', fontWeight: 600 }}>FILTER NODES:</span>
          <select
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            style={{
              background: '#0a0d14',
              color: '#f8fafc',
              border: '1px solid #23304c',
              padding: '6px 12px',
              borderRadius: 8,
              fontSize: 13,
            }}
          >
            <option value="all">All Entity Types ({graphData.nodes.length})</option>
            <option value="domain">Domains</option>
            <option value="ip_address">IP Addresses</option>
            <option value="certificate">TLS Certificates</option>
            <option value="url">URLs</option>
            <option value="report">Threat Reports</option>
          </select>

          <span style={{ fontSize: 13, color: '#94a3b8', fontWeight: 600, marginLeft: 8 }}>RELATIONSHIPS:</span>
          <select
            value={filterEdgeType}
            onChange={e => setFilterEdgeType(e.target.value)}
            style={{
              background: '#0a0d14',
              color: '#f8fafc',
              border: '1px solid #23304c',
              padding: '6px 12px',
              borderRadius: 8,
              fontSize: 13,
            }}
          >
            <option value="all">All Relationships ({graphData.edges.length})</option>
            {edgeTypes.map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <input
            type="text"
            placeholder="Focus Domain..."
            value={domainFilter}
            onChange={e => setDomainFilter(e.target.value)}
            style={{
              background: '#0a0d14',
              color: '#f8fafc',
              border: '1px solid #23304c',
              padding: '6px 12px',
              borderRadius: 8,
              fontSize: 13,
              width: 180,
            }}
          />
          <button
            onClick={() => { setPan({ x: 450, y: 300 }); setZoom(1); }}
            style={{
              background: '#23304c',
              color: '#f8fafc',
              border: 'none',
              padding: '6px 14px',
              borderRadius: 8,
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Reset View
          </button>
        </div>
      </div>

      {/* Main Canvas + Inspector Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedNode || selectedEdge ? '1fr 340px' : '1fr', height: '100%', gap: 16 }}>
        {/* SVG Graph Canvas */}
        <div
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onWheel={handleWheel}
          style={{
            background: '#0c101c',
            borderRadius: 12,
            border: '1px solid #23304c',
            overflow: 'hidden',
            position: 'relative',
            cursor: isDragging ? 'grabbing' : 'grab',
            userSelect: 'none',
          }}
        >
          {loading && (
            <div style={{
              position: 'absolute', top: 20, left: 20, zIndex: 10,
              background: 'rgba(15, 23, 42, 0.85)', padding: '6px 14px', borderRadius: 8,
              fontSize: 12, color: '#06b6d4', border: '1px solid #06b6d4',
            }}>
              Loading Investigation Topology...
            </div>
          )}

          {/* Graph Legend Overlay */}
          <div style={{
            position: 'absolute', bottom: 16, left: 16, zIndex: 10,
            background: 'rgba(15, 23, 42, 0.85)', backdropFilter: 'blur(8px)',
            padding: '10px 14px', borderRadius: 10, border: '1px solid #23304c',
            display: 'flex', gap: 14, fontSize: 11,
          }}>
            {Object.entries(ENTITY_CONFIG).slice(0, 5).map(([type, cfg]) => (
              <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: cfg.color }}></span>
                <span style={{ color: '#94a3b8' }}>{cfg.label}</span>
              </div>
            ))}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, borderLeft: '1px solid #334155', paddingLeft: 10 }}>
              <span style={{ width: 16, height: 2, background: '#6366f1' }}></span>
              <span style={{ color: '#94a3b8' }}>Strong Edge</span>
              <span style={{ width: 16, height: 2, borderTop: '2px dashed #64748b' }}></span>
              <span style={{ color: '#94a3b8' }}>Weak Edge</span>
            </div>
          </div>

          <svg width="100%" height="100%" style={{ width: '100%', height: '100%' }}>
            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              {/* Edges */}
              {filteredEdges.map(edge => {
                const src = nodePositions[edge.source_entity_id];
                const tgt = nodePositions[edge.target_entity_id];
                if (!src || !tgt) return null;

                const isSelected = selectedEdge && selectedEdge.relationship_id === edge.relationship_id;
                const isStrong = (edge.confidence || 1.0) >= 0.7;

                return (
                  <g key={edge.relationship_id} onClick={(e) => { e.stopPropagation(); setSelectedEdge(edge); setSelectedNode(null); }}>
                    <line
                      x1={src.x} y1={src.y}
                      x2={tgt.x} y2={tgt.y}
                      stroke={isSelected ? '#38bdf8' : isStrong ? '#6366f1' : '#475569'}
                      strokeWidth={isSelected ? 3.5 : isStrong ? 2.5 : 1.5}
                      strokeDasharray={isStrong ? 'none' : '4,4'}
                      strokeOpacity={isSelected ? 1.0 : isStrong ? 0.75 : 0.45}
                      style={{ cursor: 'pointer' }}
                    />
                    {/* Edge Label text at midpoint */}
                    <text
                      x={(src.x + tgt.x) / 2}
                      y={(src.y + tgt.y) / 2 - 5}
                      fill={isSelected ? '#38bdf8' : '#64748b'}
                      fontSize={10}
                      fontFamily="JetBrains Mono, monospace"
                      textAnchor="middle"
                      style={{ cursor: 'pointer', userSelect: 'none' }}
                    >
                      {edge.type}
                    </text>
                  </g>
                );
              })}

              {/* Nodes */}
              {filteredNodes.map(node => {
                const pos = nodePositions[node.entity_id] || { x: 0, y: 0 };
                const cfg = ENTITY_CONFIG[node.type] || { color: '#94a3b8', label: node.type, icon: '📍' };
                const isSelected = selectedNode && selectedNode.entity_id === node.entity_id;
                const r = node.type === 'domain' ? 24 : 18;

                return (
                  <g
                    key={node.entity_id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={(e) => { e.stopPropagation(); setSelectedNode(node); setSelectedEdge(null); }}
                    style={{ cursor: 'pointer' }}
                  >
                    {/* Outer glow ring if selected */}
                    {isSelected && (
                      <circle r={r + 8} fill="none" stroke="#38bdf8" strokeWidth={2.5} strokeDasharray="3,3" opacity={0.9} />
                    )}
                    <circle
                      r={r}
                      fill={cfg.color}
                      stroke="#0f172a"
                      strokeWidth={2.5}
                      filter="drop-shadow(0 2px 4px rgba(0,0,0,0.5))"
                    />
                    <text
                      y={4}
                      fill="#ffffff"
                      fontSize={11}
                      textAnchor="middle"
                      style={{ pointerEvents: 'none' }}
                    >
                      {cfg.icon}
                    </text>
                    {/* Node value label */}
                    <text
                      y={r + 14}
                      fill={isSelected ? '#38bdf8' : '#e2e8f0'}
                      fontSize={11}
                      fontWeight={isSelected ? '700' : '500'}
                      textAnchor="middle"
                      fontFamily="JetBrains Mono, monospace"
                      style={{ pointerEvents: 'none' }}
                    >
                      {node.value.length > 20 ? node.value.slice(0, 18) + '...' : node.value}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Inspector Panel */}
        {(selectedNode || selectedEdge) && (
          <div style={{
            background: '#151d30',
            borderRadius: 12,
            border: '1px solid #23304c',
            padding: 20,
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
          }}>
            {/* Node Inspector */}
            {selectedNode && (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{
                    background: ENTITY_CONFIG[selectedNode.type]?.color || '#6366f1',
                    color: '#fff', padding: '3px 10px', borderRadius: 6, fontSize: 11, fontWeight: 700,
                  }}>
                    {selectedNode.type.toUpperCase()}
                  </span>
                  <button
                    onClick={() => setSelectedNode(null)}
                    style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: 18 }}
                  >
                    ✕
                  </button>
                </div>

                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 700, wordBreak: 'break-all', fontFamily: 'JetBrains Mono' }}>
                    {selectedNode.value}
                  </h3>
                  <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>ID: {selectedNode.entity_id}</p>
                </div>

                {selectedNode.type === 'domain' && onSelectDomain && (
                  <button
                    onClick={() => onSelectDomain(selectedNode.value)}
                    style={{
                      background: 'linear-gradient(135deg, #4f46e5, #06b6d4)',
                      border: 'none', color: '#fff', padding: '8px 14px', borderRadius: 8,
                      fontSize: 12, fontWeight: 600, cursor: 'pointer',
                    }}
                  >
                    Scan This Domain →
                  </button>
                )}

                <div style={{ borderTop: '1px solid #23304c', paddingTop: 12 }}>
                  <h4 style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 8 }}>Timestamps</h4>
                  <div style={{ fontSize: 12, color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div><strong>First Seen:</strong> {new Date(selectedNode.first_seen).toLocaleString()}</div>
                    <div><strong>Last Seen:</strong> {new Date(selectedNode.last_seen).toLocaleString()}</div>
                    <div><strong>Associated Scans:</strong> {selectedNode.scan_ids?.length || 0}</div>
                  </div>
                </div>

                {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                  <div style={{ borderTop: '1px solid #23304c', paddingTop: 12 }}>
                    <h4 style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 8 }}>Entity Metadata</h4>
                    <pre style={{
                      background: '#0a0d14', padding: 10, borderRadius: 8, fontSize: 11,
                      color: '#06b6d4', overflowX: 'auto',
                    }}>
                      {JSON.stringify(selectedNode.metadata, null, 2)}
                    </pre>
                  </div>
                )}
              </>
            )}

            {/* Edge Inspector */}
            {selectedEdge && (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{
                    background: '#6366f1', color: '#fff', padding: '3px 10px',
                    borderRadius: 6, fontSize: 11, fontWeight: 700,
                  }}>
                    RELATIONSHIP
                  </span>
                  <button
                    onClick={() => setSelectedEdge(null)}
                    style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: 18 }}
                  >
                    ✕
                  </button>
                </div>

                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 700, color: '#38bdf8' }}>
                    {selectedEdge.type}
                  </h3>
                  <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4, display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <div><strong>Source:</strong> {selectedEdge.source_entity_id}</div>
                    <div><strong>Target:</strong> {selectedEdge.target_entity_id}</div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid #23304c', paddingTop: 12 }}>
                  <h4 style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 8 }}>Association Strength</h4>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ flex: 1, height: 8, background: '#0a0d14', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{
                        width: `${(selectedEdge.confidence || 1.0) * 100}%`,
                        height: '100%',
                        background: (selectedEdge.confidence || 1.0) >= 0.7 ? '#10b981' : '#f59e0b',
                      }} />
                    </div>
                    <span style={{ fontSize: 12, fontWeight: 700 }}>
                      {Math.round((selectedEdge.confidence || 1.0) * 100)}%
                    </span>
                  </div>
                  <p style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>
                    {(selectedEdge.confidence || 1.0) >= 0.7 ? 'Strong Direct Technical Link' : 'Corroborated Association'}
                  </p>
                </div>

                {selectedEdge.metadata && Object.keys(selectedEdge.metadata).length > 0 && (
                  <div style={{ borderTop: '1px solid #23304c', paddingTop: 12 }}>
                    <h4 style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 8 }}>Supporting Evidence</h4>
                    <div style={{ background: '#0a0d14', padding: 10, borderRadius: 8, fontSize: 12, color: '#e2e8f0' }}>
                      {selectedEdge.metadata.explanation && (
                        <p style={{ marginBottom: 8, color: '#38bdf8' }}>{selectedEdge.metadata.explanation}</p>
                      )}
                      <pre style={{ fontSize: 11, color: '#94a3b8', overflowX: 'auto' }}>
                        {JSON.stringify(selectedEdge.metadata, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}

                <div style={{ borderTop: '1px solid #23304c', paddingTop: 12, fontSize: 11, color: '#64748b' }}>
                  Observed at: {new Date(selectedEdge.created_at).toLocaleString()}
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
