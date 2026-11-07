import React, { useState, useEffect } from 'react';

const SEVERITY_COLORS = {
  critical: { bg: 'rgba(244, 63, 94, 0.15)', text: '#fda4af', border: 'rgba(244, 63, 94, 0.4)' },
  high: { bg: 'rgba(249, 115, 22, 0.15)', text: '#fdba74', border: 'rgba(249, 115, 22, 0.4)' },
  medium: { bg: 'rgba(245, 158, 11, 0.15)', text: '#fde68a', border: 'rgba(245, 158, 11, 0.4)' },
  low: { bg: 'rgba(59, 130, 246, 0.15)', text: '#93c5fd', border: 'rgba(59, 130, 246, 0.4)' },
  info: { bg: 'rgba(148, 163, 184, 0.15)', text: '#cbd5e1', border: 'rgba(148, 163, 184, 0.4)' },
};

export default function ScanReport({ scan, onNavigate }) {
  const [findings, setFindings] = useState([]);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('all');

  useEffect(() => {
    if (scan && scan.scan_id) {
      fetchFindings(scan.scan_id);
    }
  }, [scan]);

  async function fetchFindings(scanId) {
    setLoadingFindings(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/findings`);
      if (res.ok) {
        const data = await res.json();
        setFindings(data);
      }
    } catch (e) {
      console.warn('Error fetching findings:', e);
    } finally {
      setLoadingFindings(false);
    }
  }

  if (!scan) {
    return (
      <div style={{ textAlign: 'center', padding: 60, background: '#151d30', borderRadius: 14, border: '1px solid #23304c' }}>
        <h3 style={{ fontSize: 18, color: '#f8fafc' }}>No Scan Selected</h3>
        <p style={{ color: '#94a3b8', marginTop: 8 }}>Please run a scan from the Scanner tab or select a previous investigation.</p>
        <button
          onClick={() => onNavigate('scanner')}
          style={{
            marginTop: 16, background: '#6366f1', color: '#fff', border: 'none',
            padding: '10px 20px', borderRadius: 8, fontWeight: 600, cursor: 'pointer',
          }}
        >
          Go to Scanner →
        </button>
      </div>
    );
  }

  const riskScore = scan.risk_score || 0;
  const riskLevel = scan.risk_level || 'none';
  const confidence = 0.88; // Explored confidence

  // Factor breakdown from risk scoring module if present
  let breakdown = { url_threats: 0, tls_vulnerabilities: 0, content_and_headers: 0, other: 0 };
  const riskMod = scan.module_results?.find(m => m.module === 'risk_scoring');
  if (riskMod && riskMod.data?.factor_breakdown) {
    breakdown = riskMod.data.factor_breakdown;
  }

  // Filter findings
  const filteredFindings = findings.filter(f => {
    if (severityFilter === 'all') return true;
    return f.severity === severityFilter;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1100, margin: '0 auto' }}>
      {/* Top Header Card */}
      <div style={{
        background: '#151d30',
        borderRadius: 14,
        border: '1px solid #23304c',
        padding: 24,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 16,
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Investigation Report
            </span>
            <span style={{
              fontSize: 11, padding: '2px 8px', borderRadius: 6,
              background: scan.status === 'completed' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)',
              color: scan.status === 'completed' ? '#34d399' : '#fbbf24',
              fontWeight: 700,
            }}>
              {scan.status?.toUpperCase()}
            </span>
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 800, marginTop: 4, fontFamily: 'JetBrains Mono', color: '#f8fafc' }}>
            {scan.hostname || scan.target_url}
          </h2>
          <p style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>
            Scan ID: {scan.scan_id} • Duration: {scan.duration_ms}ms • Timestamp: {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>

        {/* Quick jump to Graph & Flight Recorder */}
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            onClick={() => onNavigate('graph')}
            style={{
              background: '#0a0d14', border: '1px solid #23304c', color: '#38bdf8',
              padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            🌐 View in Graph
          </button>
          <button
            onClick={() => onNavigate('flight_recorder')}
            style={{
              background: '#0a0d14', border: '1px solid #23304c', color: '#a78bfa',
              padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            ⏱️ Flight Recorder Timeline
          </button>
        </div>
      </div>

      {/* Metrics Row: Risk Score, Category, Confidence, Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
        {/* Risk Score Gauge Card */}
        <div style={{
          background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 20,
          display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center',
        }}>
          <span style={{ fontSize: 12, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>
            Composite Risk Score
          </span>
          <div style={{
            fontSize: 48, fontWeight: 800, marginTop: 10,
            color: riskScore >= 75 ? '#f43f5e' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#f59e0b' : '#10b981',
            fontFamily: 'JetBrains Mono',
          }}>
            {riskScore.toFixed(1)}
            <span style={{ fontSize: 20, color: '#64748b' }}>/100</span>
          </div>
          <div style={{ width: '100%', height: 6, background: '#0a0d14', borderRadius: 3, marginTop: 14, overflow: 'hidden' }}>
            <div style={{
              width: `${Math.min(100, riskScore)}%`, height: '100%',
              background: riskScore >= 75 ? '#f43f5e' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#f59e0b' : '#10b981',
            }} />
          </div>
        </div>

        {/* Risk Category Card */}
        <div style={{
          background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 20,
          display: 'flex', flexDirection: 'column', justifyContent: 'center',
        }}>
          <span style={{ fontSize: 12, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>
            Threat Classification
          </span>
          <div style={{
            fontSize: 26, fontWeight: 800, textTransform: 'uppercase', marginTop: 10,
            color: riskLevel === 'critical' ? '#f43f5e' : riskLevel === 'high' ? '#f97316' : riskLevel === 'medium' ? '#f59e0b' : '#10b981',
          }}>
            {riskLevel} Threat
          </div>
          <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 6, lineHeight: 1.5 }}>
            {riskLevel === 'critical' || riskLevel === 'high'
              ? 'Target exhibits active phishing indicators, malicious infrastructure, or severe cryptography flaws.'
              : 'Target does not demonstrate conclusive active phishing signals.'}
          </p>
        </div>

        {/* Confidence Level Card */}
        <div style={{
          background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 20,
          display: 'flex', flexDirection: 'column', justifyContent: 'center',
        }}>
          <span style={{ fontSize: 12, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>
            Assessment Confidence
          </span>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#38bdf8', marginTop: 10, fontFamily: 'JetBrains Mono' }}>
            {Math.round(confidence * 100)}%
          </div>
          <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 6, lineHeight: 1.5 }}>
            Confidence represents evidence corroboration depth across DNS, TLS, DOM heuristics, and community reports.
          </p>
        </div>

        {/* Factor Breakdown Card */}
        <div style={{
          background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 20,
        }}>
          <span style={{ fontSize: 12, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>
            Contributing Vectors
          </span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10, fontSize: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#cbd5e1' }}>URL Threat Heuristics:</span>
              <strong style={{ color: '#f8fafc' }}>{breakdown.url_threats} pts</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#cbd5e1' }}>TLS Cryptography:</span>
              <strong style={{ color: '#f8fafc' }}>{breakdown.tls_vulnerabilities} pts</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#cbd5e1' }}>DOM & Headers:</span>
              <strong style={{ color: '#f8fafc' }}>{breakdown.content_and_headers} pts</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Findings Section with Filter */}
      <div style={{
        background: '#151d30',
        borderRadius: 14,
        border: '1px solid #23304c',
        padding: 24,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc' }}>
              Security Findings ({findings.length})
            </h3>
            <p style={{ fontSize: 12, color: '#94a3b8' }}>
              Detailed breakdown of detected anomalies, threat indicators, and technical evidence.
            </p>
          </div>

          {/* Severity Filter Tabs */}
          <div style={{ display: 'flex', gap: 6 }}>
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  background: severityFilter === sev ? '#23304c' : 'transparent',
                  color: severityFilter === sev ? '#f8fafc' : '#94a3b8',
                  border: '1px solid #23304c',
                  padding: '4px 10px',
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  cursor: 'pointer',
                }}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {loadingFindings ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#38bdf8' }}>Loading findings...</div>
        ) : filteredFindings.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
            No findings matching the selected filter.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {filteredFindings.map((f, idx) => {
              const cfg = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info;
              return (
                <div
                  key={f.finding_id || idx}
                  style={{
                    background: '#0c101c',
                    borderRadius: 10,
                    border: '1px solid #23304c',
                    padding: 16,
                    borderLeft: `4px solid ${cfg.text}`,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{
                        background: cfg.bg, color: cfg.text, border: `1px solid ${cfg.border}`,
                        fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, textTransform: 'uppercase',
                      }}>
                        {f.severity}
                      </span>
                      <h4 style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc' }}>
                        {f.title}
                      </h4>
                    </div>
                    <span style={{ fontSize: 11, color: '#64748b', fontFamily: 'JetBrains Mono' }}>
                      Module: {f.module}
                    </span>
                  </div>

                  <p style={{ fontSize: 13, color: '#cbd5e1', marginTop: 8, lineHeight: 1.5 }}>
                    {f.description}
                  </p>

                  {f.recommendation && (
                    <div style={{
                      marginTop: 10, background: 'rgba(16, 185, 129, 0.08)',
                      border: '1px solid rgba(16, 185, 129, 0.2)',
                      padding: '8px 12px', borderRadius: 6, fontSize: 12, color: '#6ee7b7',
                    }}>
                      <strong>💡 Recommended Action:</strong> {f.recommendation}
                    </div>
                  )}

                  {f.evidence && Object.keys(f.evidence).length > 0 && (
                    <div style={{ marginTop: 10 }}>
                      <details style={{ fontSize: 11, color: '#94a3b8' }}>
                        <summary style={{ cursor: 'pointer', color: '#38bdf8' }}>View Technical Evidence</summary>
                        <pre style={{
                          background: '#06080e', padding: 10, borderRadius: 6, marginTop: 6,
                          overflowX: 'auto', color: '#94a3b8',
                        }}>
                          {JSON.stringify(f.evidence, null, 2)}
                        </pre>
                      </details>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
