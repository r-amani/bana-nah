import React, { useState, useEffect } from 'react';

const METRIC_CONFIG = [
  { key: 'totalScans', label: 'Total Scans', color: '#0284c7', sub: 'Completed investigations' },
  { key: 'highRiskScans', label: 'High & Critical Threats', color: '#e11d48', sub: 'Risk score \u2265 50' },
  { key: 'totalReports', label: 'Community Reports', color: '#d97706', sub: 'Crowdsourced submissions' },
  { key: 'graphNodes', label: 'Investigation Graph Nodes', color: '#0d9488', sub: 'Correlated infrastructure entities' },
];

export default function Dashboard({ onNavigate, onSelectScan }) {
  const [stats, setStats] = useState({ totalScans: 0, highRiskScans: 0, totalReports: 0, graphNodes: 0, recentScans: [] });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const [sRes, rRes, gRes] = await Promise.all([fetch('/api/scans?limit=10'), fetch('/api/reports?limit=10'), fetch('/api/graph?max_nodes=100')]);
        const scans = sRes.ok ? await sRes.json() : [];
        const reports = rRes.ok ? await rRes.json() : [];
        const graph = gRes.ok ? await gRes.json() : { nodes: [] };
        setStats({
          totalScans: scans.length,
          highRiskScans: scans.filter(s => (s.risk_score || 0) >= 50).length,
          totalReports: reports.length,
          graphNodes: graph.nodes?.length || 0,
          recentScans: scans,
        });
      } catch (e) {
        console.warn('Dashboard fetch error:', e);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1160, margin: '0 auto' }}>
      <div style={{ background: 'linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%)', border: '1.5px solid #bae6fd', borderRadius: 20, padding: '28px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, boxShadow: '0 4px 16px rgba(2, 132, 199, 0.06)' }}>
        <div>
          <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, letterSpacing: '.06em', textTransform: 'uppercase' }}>Threat Operations Overview</span>
          <h2 style={{ fontSize: 26, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>PHANTOM Cyber Threat Intelligence Hub</h2>
          <p style={{ fontSize: 14, color: '#475569', marginTop: 4 }}>Continuous passive monitoring, lexical homograph analysis, and investigation graph topology.</p>
        </div>
        <button
          onClick={() => onNavigate('scanner')}
          style={{ background: 'linear-gradient(135deg, #0284c7, #0ea5e9)', color: '#ffffff', border: 'none', padding: '12px 24px', borderRadius: 999, fontSize: 14, fontWeight: 700, cursor: 'pointer', boxShadow: '0 4px 14px rgba(2, 132, 199, 0.3)' }}
        >
          New URL Scan →
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
        {METRIC_CONFIG.map(m => (
          <div key={m.key} style={{ background: '#ffffff', padding: '22px 24px', borderRadius: 16, border: '1.5px solid var(--border-subtle)', boxShadow: 'var(--shadow-sm)' }}>
            <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.06em', color: '#64748b', textTransform: 'uppercase' }}>{m.label}</span>
            <div style={{ fontSize: 34, fontWeight: 800, color: m.color, marginTop: 8, fontFamily: 'IBM Plex Mono' }}>{stats[m.key]}</div>
            <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>{m.sub}</p>
          </div>
        ))}
      </div>

      <div style={{ background: '#ffffff', borderRadius: 18, border: '1.5px solid var(--border-subtle)', padding: '24px 28px', boxShadow: 'var(--shadow-sm)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div>
            <h3 style={{ fontSize: 17, fontWeight: 800, color: '#0f172a' }}>Recent Threat Investigations</h3>
            <p style={{ fontSize: 13, color: '#64748b', marginTop: 2 }}>Historical scans recorded across all intelligence modules.</p>
          </div>
          <button onClick={() => onNavigate('scanner')} style={{ background: '#f0f9ff', border: '1.5px solid #bae6fd', color: '#0284c7', padding: '6px 15px', borderRadius: 999, fontSize: 13, fontWeight: 700, cursor: 'pointer' }}>
            Launch Investigation →
          </button>
        </div>

        {stats.recentScans.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: '#94a3b8' }}>
            {loading ? 'Loading intelligence metrics...' : 'No recent scans executed yet. Use the Scanner tab to run your first investigation.'}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {stats.recentScans.map(scan => {
              const score = scan.risk_score || 0;
              const isHigh = score >= 50;
              const isSusp = score >= 25 && score < 50;
              const [bg, color, border] = isHigh ? ['#fff1f2', '#e11d48', '#fecdd3'] : isSusp ? ['#fefce8', '#b45309', '#fef08a'] : ['#ecfdf5', '#059669', '#a7f3d0'];

              return (
                <div
                  key={scan.scan_id}
                  onClick={() => { onSelectScan(scan); onNavigate('report'); }}
                  style={{ background: '#f8fafc', borderRadius: 12, border: '1px solid #e2e8f0', padding: '14px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', transition: 'all 0.15s' }}
                  onMouseEnter={e => { e.currentTarget.style.background = '#f0f7ff'; e.currentTarget.style.borderColor = '#bae6fd'; }}
                  onMouseLeave={e => { e.currentTarget.style.background = '#f8fafc'; e.currentTarget.style.borderColor = '#e2e8f0'; }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                    <span style={{ fontSize: 12, fontWeight: 800, padding: '4px 10px', borderRadius: 999, background: bg, color, border: `1px solid ${border}`, fontFamily: 'IBM Plex Mono' }}>
                      {score.toFixed(1)}/100
                    </span>
                    <div>
                      <h4 style={{ fontSize: 14, fontWeight: 700, color: '#0f172a', fontFamily: 'IBM Plex Mono' }}>{scan.hostname || scan.target_url}</h4>
                      <p style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>{new Date(scan.created_at).toLocaleString()} • Duration: {scan.duration_ms}ms</p>
                    </div>
                  </div>
                  <span style={{ fontSize: 13, color: '#0284c7', fontWeight: 600 }}>Inspect Report →</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
