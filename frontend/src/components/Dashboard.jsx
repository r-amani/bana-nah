import React, { useState, useEffect } from 'react';

export default function Dashboard({ onNavigate, onSelectScan }) {
  const [stats, setStats] = useState({
    totalScans: 0,
    highRiskScans: 0,
    totalReports: 0,
    graphNodes: 0,
    recentScans: [],
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardMetrics();
  }, []);

  async function fetchDashboardMetrics() {
    setLoading(true);
    try {
      const [scansRes, reportsRes, graphRes] = await Promise.all([
        fetch('/api/scans?limit=10'),
        fetch('/api/reports?limit=10'),
        fetch('/api/graph?max_nodes=100'),
      ]);

      const scans = scansRes.ok ? await scansRes.json() : [];
      const reports = reportsRes.ok ? await reportsRes.json() : [];
      const graph = graphRes.ok ? await graphRes.json() : { nodes: [] };

      const highRisk = scans.filter(s => (s.risk_score || 0) >= 50).length;

      setStats({
        totalScans: scans.length,
        highRiskScans: highRisk,
        totalReports: reports.length,
        graphNodes: graph.nodes?.length || 0,
        recentScans: scans,
      });
    } catch (e) {
      console.warn('Dashboard metrics fetch error:', e);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1100, margin: '0 auto' }}>
      {/* Platform Title Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(6, 182, 212, 0.08) 100%)',
        border: '1px solid #23304c',
        borderRadius: 14,
        padding: 24,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 16,
      }}>
        <div>
          <span style={{ fontSize: 12, color: '#38bdf8', fontWeight: 700, textTransform: 'uppercase' }}>
            Threat Operations Overview
          </span>
          <h2 style={{ fontSize: 24, fontWeight: 800, color: '#f8fafc', marginTop: 4 }}>
            PHANTOM Cyber Threat Intelligence Hub
          </h2>
          <p style={{ fontSize: 13, color: '#94a3b8', marginTop: 4 }}>
            Continuous passive monitoring, lexical homograph analysis, and investigation graph topology.
          </p>
        </div>

        <button
          onClick={() => onNavigate('scanner')}
          style={{
            background: 'linear-gradient(135deg, #6366f1, #06b6d4)',
            color: '#fff', border: 'none', padding: '10px 20px', borderRadius: 8,
            fontSize: 13, fontWeight: 700, cursor: 'pointer',
          }}
        >
          New URL Scan →
        </button>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
        <div style={{ background: '#151d30', padding: 20, borderRadius: 12, border: '1px solid #23304c' }}>
          <span style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase' }}>Total Scans</span>
          <div style={{ fontSize: 32, fontWeight: 800, color: '#f8fafc', marginTop: 8, fontFamily: 'JetBrains Mono' }}>
            {stats.totalScans}
          </div>
          <p style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>Completed investigations</p>
        </div>

        <div style={{ background: '#151d30', padding: 20, borderRadius: 12, border: '1px solid #23304c' }}>
          <span style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase' }}>High & Critical Threats</span>
          <div style={{ fontSize: 32, fontWeight: 800, color: '#f43f5e', marginTop: 8, fontFamily: 'JetBrains Mono' }}>
            {stats.highRiskScans}
          </div>
          <p style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>Risk score &gt;= 50</p>
        </div>

        <div style={{ background: '#151d30', padding: 20, borderRadius: 12, border: '1px solid #23304c' }}>
          <span style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase' }}>Community Reports</span>
          <div style={{ fontSize: 32, fontWeight: 800, color: '#f59e0b', marginTop: 8, fontFamily: 'JetBrains Mono' }}>
            {stats.totalReports}
          </div>
          <p style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>Crowdsourced submissions</p>
        </div>

        <div style={{ background: '#151d30', padding: 20, borderRadius: 12, border: '1px solid #23304c' }}>
          <span style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase' }}>Investigation Graph Nodes</span>
          <div style={{ fontSize: 32, fontWeight: 800, color: '#38bdf8', marginTop: 8, fontFamily: 'JetBrains Mono' }}>
            {stats.graphNodes}
          </div>
          <p style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>Correlated infrastructure entities</p>
        </div>
      </div>

      {/* Recent Scans Activity Table */}
      <div style={{ background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
            Recent Threat Investigations
          </h3>
          <button
            onClick={() => onNavigate('scanner')}
            style={{ background: 'transparent', border: 'none', color: '#38bdf8', fontSize: 12, cursor: 'pointer' }}
          >
            Launch Investigation →
          </button>
        </div>

        {stats.recentScans.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
            No recent scans executed yet.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {stats.recentScans.map(scan => {
              const score = scan.risk_score || 0;
              const isHigh = score >= 50;

              return (
                <div
                  key={scan.scan_id}
                  onClick={() => { onSelectScan(scan); onNavigate('report'); }}
                  style={{
                    background: '#0c101c', borderRadius: 8, border: '1px solid #23304c', padding: 14,
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    cursor: 'pointer', transition: 'border-color 0.15s ease',
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = '#38bdf8'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = '#23304c'}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{
                      fontSize: 11, fontWeight: 800, padding: '3px 8px', borderRadius: 4,
                      background: isHigh ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                      color: isHigh ? '#fda4af' : '#6ee7b7',
                    }}>
                      {score.toFixed(1)}/100
                    </span>
                    <div>
                      <h4 style={{ fontSize: 13, fontWeight: 600, color: '#f8fafc', fontFamily: 'JetBrains Mono' }}>
                        {scan.hostname || scan.target_url}
                      </h4>
                      <p style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
                        {new Date(scan.created_at).toLocaleString()} • Duration: {scan.duration_ms}ms
                      </p>
                    </div>
                  </div>

                  <span style={{ fontSize: 12, color: '#38bdf8', fontWeight: 600 }}>
                    Inspect Report →
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
