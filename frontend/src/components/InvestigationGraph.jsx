import React, { useState, useEffect } from 'react';

// Entity type badges and colors for light blue & white theme
const ENTITY_CONFIG = {
  domain: { color: '#0284c7', label: 'Domain', icon: '🌐' },
  ip_address: { color: '#0d9488', label: 'IP Address', icon: '🖥️' },
  certificate: { color: '#059669', label: 'Certificate', icon: '🔒' },
  url: { color: '#d97706', label: 'URL', icon: '🔗' },
  report: { color: '#e11d48', label: 'Report', icon: '🚩' },
  nameserver: { color: '#7c3aed', label: 'Nameserver', icon: '📡' },
  organization: { color: '#db2777', label: 'Organization', icon: '🏢' },
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

    if (nodes.length === 0) {
      setNodePositions({});
      return;
    }

    if (centerNode) {
      pos[centerNode.entity_id] = { x: 0, y: 0 };
    }

    const otherNodes = nodes.filter(n => n !== centerNode);
    const radiusStep = 180;
    const total = otherNodes.length;

    otherNodes.forEach((node, i) => {
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

  const edgeTypes = Array.from(new Set(graphData.edges.map(e => e.type)));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)', gap: 16 }}>
      {/* Top Filter Bar */}
      <div style={{
        background: '#ffffff',
        padding: '12px 20px',
        borderRadius: 16,
        border: '1.5px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
            Filter Nodes:
          </span>
          <select
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            style={{
              background: '#f8fafc',
              color: '#0f172a',
              border: '1.5px solid #cbd5e1',
              padding: '6px 12px',
              borderRadius: 8,
              fontSize: 13,
              outline: 'none',
            }}
          >
            <option value="all">All Entity Types ({graphData.nodes.length})</option>
            <option value="domain">Domains</option>
            <option value="ip_address">IP Addresses</option>
            <option value="certificate">TLS Certificates</option>
            <option value="url">URLs</option>
            <option value="report">Threat Reports</option>
          </select>

          <span style={{ fontSize: 12, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', marginLeft: 4 }}>
            Relationships:
          </span>
          <select
            value={filterEdgeType}
            onChange={e => setFilterEdgeType(e.target.value)}
            style={{
              background: '#f8fafc',
              color: '#0f172a',
              border: '1.5px solid #cbd5e1',
              padding: '6px 12px',
              borderRadius: 8,
              fontSize: 13,
              outline: 'none',
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
              background: '#f8fafc',
              color: '#0f172a',
              border: '1.5px solid #cbd5e1',
              padding: '6px 14px',
              borderRadius: 999,
              fontSize: 13,
              fontFamily: 'IBM Plex Mono',
              outline: 'none',
              width: 180,
            }}
          />
          <button
            onClick={() => { setPan({ x: 450, y: 300 }); setZoom(1); }}
            style={{
              background: '#f0f9ff',
              border: '1.5px solid #bae6fd',
              color: '#0284c7',
              padding: '6px 15px',
              borderRadius: 999,
              fontSize: 12.5,
              fontWeight: 700,
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
            background: '#f8fafc',
            borderRadius: 16,
            border: '1.5px solid var(--border-subtle)',
            overflow: 'hidden',
            position: 'relative',
            cursor: isDragging ? 'grabbing' : 'grab',
            userSelect: 'none',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          {loading && (
            <div style={{
              position: 'absolute', top: 20, left: 20, zIndex: 10,
              background: '#ffffff', padding: '8px 16px', borderRadius: 999,
              fontSize: 12, fontWeight: 700, color: '#0284c7',
              border: '1.5px solid #bae6fd', boxShadow: 'var(--shadow-sm)',
            }}>
              Loading Investigation Topology...
            </div>
          )}

          {/* Graph Legend Overlay */}
          <div style={{
            position: 'absolute', bottom: 16, left: 16, zIndex: 10,
            background: 'rgba(255, 255, 255, 0.94)', backdropFilter: 'blur(8px)',
            padding: '10px 16px', borderRadius: 12, border: '1px solid #cbd5e1',
            display: 'flex', gap: 14, fontSize: 11.5, boxShadow: 'var(--shadow-sm)',
            flexWrap: 'wrap',
          }}>
            {Object.entries(ENTITY_CONFIG).slice(0, 5).map(([type, cfg]) => (
              <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: cfg.color }}></span>
                <span style={{ color: '#475569', fontWeight: 600 }}>{cfg.label}</span>
              </div>
            ))}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, borderLeft: '1px solid #e2e8f0', paddingLeft: 10 }}>
              <span style={{ width: 16, height: 2, background: '#0284c7' }}></span>
              <span style={{ color: '#64748b' }}>Strong</span>
              <span style={{ width: 16, height: 2, borderTop: '2px dashed #94a3b8' }}></span>
              <span style={{ color: '#64748b' }}>Corroborated</span>
            </div>
          </div>

          <svg width="100%" height="100%" style={{ width: '100%', height: '100%' }}>
            {/* Subtle light background grid dots */}
            <defs>
              <pattern id="graph-dots" width="30" height="30" patternUnits="userSpaceOnUse">
                <circle cx="2" cy="2" r="1.2" fill="#cbd5e1" opacity="0.6" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#graph-dots)" />

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
                      stroke={isSelected ? '#0284c7' : isStrong ? '#0284c7' : '#94a3b8'}
                      strokeWidth={isSelected ? 3.5 : isStrong ? 2.2 : 1.5}
                      strokeDasharray={isStrong ? 'none' : '4,4'}
                      strokeOpacity={isSelected ? 1.0 : isStrong ? 0.7 : 0.4}
                      style={{ cursor: 'pointer' }}
                    />
                    <text
                      x={(src.x + tgt.x) / 2}
                      y={(src.y + tgt.y) / 2 - 5}
                      fill={isSelected ? '#0284c7' : '#64748b'}
                      fontSize={10}
                      fontWeight="600"
                      fontFamily="IBM Plex Mono, monospace"
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
                const cfg = ENTITY_CONFIG[node.type] || { color: '#64748b', label: node.type, icon: '📍' };
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
                      <circle r={r + 8} fill="none" stroke="#0284c7" strokeWidth={2.5} strokeDasharray="3,3" opacity={0.9} />
                    )}
                    <circle
                      r={r}
                      fill={cfg.color}
                      stroke="#ffffff"
                      strokeWidth={2.5}
                      filter="drop-shadow(0 2px 5px rgba(0,0,0,0.15))"
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
                      fill={isSelected ? '#0284c7' : '#0f172a'}
                      fontSize={11.5}
                      fontWeight={isSelected ? '800' : '600'}
                      textAnchor="middle"
                      fontFamily="IBM Plex Mono, monospace"
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
            background: '#ffffff',
            borderRadius: 16,
            border: '1.5px solid var(--border-subtle)',
            padding: 20,
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
            boxShadow: 'var(--shadow-sm)',
          }}>
            {/* Node Inspector */}
            {selectedNode && (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{
                    background: ENTITY_CONFIG[selectedNode.type]?.color || '#0284c7',
                    color: '#ffffff',
                    padding: '3px 10px',
                    borderRadius: 999,
                    fontSize: 11,
                    fontWeight: 700,
                  }}>
                    {selectedNode.type.toUpperCase()}
                  </span>
                  <button
                    onClick={() => setSelectedNode(null)}
                    style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: 18 }}
                  >
                    ✕
                  </button>
                </div>

                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 700, wordBreak: 'break-all', fontFamily: 'IBM Plex Mono', color: '#0f172a' }}>
                    {selectedNode.value}
                  </h3>
                  <p style={{ fontSize: 12, color: '#64748b', marginTop: 4, fontFamily: 'IBM Plex Mono' }}>
                    ID: {selectedNode.entity_id}
                  </p>
                </div>

                {selectedNode.type === 'domain' && onSelectDomain && (
                  <button
                    onClick={() => onSelectDomain(selectedNode.value)}
                    style={{
                      background: 'linear-gradient(135deg, #0284c7, #0ea5e9)',
                      border: 'none',
                      color: '#ffffff',
                      padding: '9px 16px',
                      borderRadius: 999,
                      fontSize: 13,
                      fontWeight: 700,
                      cursor: 'pointer',
                      boxShadow: '0 3px 10px rgba(2, 132, 199, 0.28)',
                    }}
                  >
                    Scan This Domain →
                  </button>
                )}

                <div style={{ borderTop: '1px solid #e2e8f0', paddingTop: 12 }}>
                  <h4 style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 8 }}>
                    Timestamps
                  </h4>
                  <div style={{ fontSize: 12, color: '#334155', display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div><strong>First Seen:</strong> {new Date(selectedNode.first_seen).toLocaleString()}</div>
                    <div><strong>Last Seen:</strong> {new Date(selectedNode.last_seen).toLocaleString()}</div>
                    <div><strong>Associated Scans:</strong> {selectedNode.scan_ids?.length || 0}</div>
                  </div>
                </div>

                {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                  <div style={{ borderTop: '1px solid #e2e8f0', paddingTop: 12 }}>
                    <h4 style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 8 }}>
                      Entity Metadata
                    </h4>
                    <pre style={{
                      background: '#f8fafc',
                      border: '1px solid #e2e8f0',
                      padding: 10,
                      borderRadius: 8,
                      fontSize: 11,
                      color: '#0369a1',
                      overflowX: 'auto',
                      fontFamily: 'IBM Plex Mono',
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
                    background: '#0284c7',
                    color: '#ffffff',
                    padding: '3px 10px',
                    borderRadius: 999,
                    fontSize: 11,
                    fontWeight: 700,
                  }}>
                    RELATIONSHIP
                  </span>
                  <button
                    onClick={() => setSelectedEdge(null)}
                    style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: 18 }}
                  >
                    ✕
                  </button>
                </div>

                <div>
                  <h3 style={{ fontSize: 15, fontWeight: 700, color: '#0284c7', fontFamily: 'IBM Plex Mono' }}>
                    {selectedEdge.type}
                  </h3>
                  <div style={{ fontSize: 12, color: '#64748b', marginTop: 4, display: 'flex', flexDirection: 'column', gap: 2, fontFamily: 'IBM Plex Mono' }}>
                    <div><strong>Source:</strong> {selectedEdge.source_entity_id}</div>
                    <div><strong>Target:</strong> {selectedEdge.target_entity_id}</div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid #e2e8f0', paddingTop: 12 }}>
                  <h4 style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 8 }}>
                    Association Strength
                  </h4>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ flex: 1, height: 8, background: '#f1f5f9', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{
                        width: `${(selectedEdge.confidence || 1.0) * 100}%`,
                        height: '100%',
                        background: (selectedEdge.confidence || 1.0) >= 0.7 ? '#059669' : '#d97706',
                      }} />
                    </div>
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
                      {Math.round((selectedEdge.confidence || 1.0) * 100)}%
                    </span>
                  </div>
                  <p style={{ fontSize: 11.5, color: '#64748b', marginTop: 4 }}>
                    {(selectedEdge.confidence || 1.0) >= 0.7 ? 'Strong Direct Technical Link' : 'Corroborated Association'}
                  </p>
                </div>

                {selectedEdge.metadata && Object.keys(selectedEdge.metadata).length > 0 && (
                  <div style={{ borderTop: '1px solid #e2e8f0', paddingTop: 12 }}>
                    <h4 style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 8 }}>
                      Supporting Evidence
                    </h4>
                    <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', padding: 10, borderRadius: 8, fontSize: 12, color: '#334155' }}>
                      {selectedEdge.metadata.explanation && (
                        <p style={{ marginBottom: 8, color: '#0284c7', fontWeight: 600 }}>{selectedEdge.metadata.explanation}</p>
                      )}
                      <pre style={{ fontSize: 11, color: '#0369a1', overflowX: 'auto', fontFamily: 'IBM Plex Mono' }}>
                        {JSON.stringify(selectedEdge.metadata, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}

                <div style={{ borderTop: '1px solid #e2e8f0', paddingTop: 12, fontSize: 11, color: '#94a3b8' }}>
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
