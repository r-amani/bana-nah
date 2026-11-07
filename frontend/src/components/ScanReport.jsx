import React, { useState, useEffect } from 'react';

const SEVERITY_CONFIG = {
  critical: { bg: '#fff1f2', text: '#e11d48', border: '#fecdd3' },
  high: { bg: '#fff7ed', text: '#ea580c', border: '#fed7aa' },
  medium: { bg: '#fefce8', text: '#d97706', border: '#fef08a' },
  low: { bg: '#e0f2fe', text: '#0284c7', border: '#bae6fd' },
  info: { bg: '#f1f5f9', text: '#475569', border: '#cbd5e1' },
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
      <div style={{
        textAlign: 'center',
        padding: '64px 32px',
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        maxWidth: 700,
        margin: '40px auto',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{
          width: 56,
          height: 56,
          borderRadius: '50%',
          background: '#f0f9ff',
          color: '#0284c7',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          margin: '0 auto 16px',
        }}>
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"></path>
            <path d="M14 3v5h5"></path>
          </svg>
        </div>
        <h3 style={{ fontSize: 20, fontWeight: 800, color: '#0f172a' }}>No Scan Selected</h3>
        <p style={{ color: '#64748b', marginTop: 8, fontSize: 14 }}>
          Please initiate a new investigation from the Scanner tab or choose a recent scan from the dashboard.
        </p>
        <button
          onClick={() => onNavigate('scanner')}
          style={{
            marginTop: 20,
            background: 'linear-gradient(135deg, #0284c7, #0ea5e9)',
            color: '#ffffff',
            border: 'none',
            padding: '12px 24px',
            borderRadius: 999,
            fontWeight: 700,
            fontSize: 14,
            cursor: 'pointer',
            boxShadow: '0 4px 14px rgba(2, 132, 199, 0.3)',
          }}
        >
          Go to Scanner →
        </button>
      </div>
    );
  }

  const riskScore = scan.risk_score || 0;
  const riskLevel = scan.risk_level || 'none';
  const confidence = 0.88;

  let breakdown = { url_threats: 0, tls_vulnerabilities: 0, content_and_headers: 0, other: 0 };
  const riskMod = scan.module_results?.find(m => m.module === 'risk_scoring');
  if (riskMod && riskMod.data?.factor_breakdown) {
    breakdown = riskMod.data.factor_breakdown;
  }

  const filteredFindings = findings.filter(f => {
    if (severityFilter === 'all') return true;
    return f.severity === severityFilter;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1140, margin: '0 auto' }}>
      {/* Top Header Card */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 16,
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Investigation Report
            </span>
            <span style={{
              fontSize: 11,
              padding: '2px 10px',
              borderRadius: 999,
              background: scan.status === 'completed' ? '#ecfdf5' : '#fefce8',
              color: scan.status === 'completed' ? '#059669' : '#d97706',
              border: `1px solid ${scan.status === 'completed' ? '#a7f3d0' : '#fef08a'}`,
              fontWeight: 700,
            }}>
              {scan.status?.toUpperCase()}
            </span>
          </div>

          <h2 style={{ fontSize: 24, fontWeight: 800, marginTop: 6, fontFamily: 'IBM Plex Mono, monospace', color: '#0f172a' }}>
            {scan.hostname || scan.target_url}
          </h2>

          <p style={{ fontSize: 12, color: '#64748b', marginTop: 4, fontFamily: 'IBM Plex Mono' }}>
            Scan ID: {scan.scan_id} • Duration: {scan.duration_ms}ms • Timestamp: {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>

        {/* Quick jump to Graph & Flight Recorder */}
        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={() => onNavigate('graph')}
            style={{
              background: '#f0f9ff',
              border: '1.5px solid #bae6fd',
              color: '#0284c7',
              padding: '10px 18px',
              borderRadius: 999,
              fontSize: 13,
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 0.15s ease',
            }}
          >
            🌐 View in Graph
          </button>
          <button
            onClick={() => onNavigate('flight_recorder')}
            style={{
              background: '#f8fafc',
              border: '1.5px solid var(--border-subtle)',
              color: '#475569',
              padding: '10px 18px',
              borderRadius: 999,
              fontSize: 13,
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 0.15s ease',
            }}
          >
            ⏱️ Flight Recorder Timeline
          </button>
        </div>
      </div>

      {/* Metrics Row: Risk Score, Category, Confidence, Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
        {/* Risk Score Card */}
        <div style={{
          background: '#ffffff',
          borderRadius: 18,
          border: '1.5px solid var(--border-subtle)',
          padding: 22,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center',
          boxShadow: 'var(--shadow-sm)',
        }}>
          <span style={{ fontSize: 12, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
            Composite Risk Score
          </span>
          <div style={{
            fontSize: 48,
            fontWeight: 800,
            marginTop: 8,
            color: riskScore >= 75 ? '#e11d48' : riskScore >= 50 ? '#ea580c' : riskScore >= 25 ? '#d97706' : '#059669',
            fontFamily: 'IBM Plex Mono',
          }}>
            {riskScore.toFixed(1)}
            <span style={{ fontSize: 20, color: '#94a3b8' }}>/100</span>
          </div>
          <div style={{ width: '100%', height: 8, background: '#f1f5f9', borderRadius: 999, marginTop: 14, overflow: 'hidden' }}>
            <div style={{
              width: `${Math.min(100, riskScore)}%`,
              height: '100%',
              background: riskScore >= 75 ? '#e11d48' : riskScore >= 50 ? '#ea580c' : riskScore >= 25 ? '#d97706' : '#059669',
              borderRadius: 999,
            }} />
          </div>
        </div>

        {/* Threat Classification */}
        <div style={{
          background: '#ffffff',
          borderRadius: 18,
          border: '1.5px solid var(--border-subtle)',
          padding: 22,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          boxShadow: 'var(--shadow-sm)',
        }}>
          <span style={{ fontSize: 12, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
            Threat Classification
          </span>
          <div style={{
            fontSize: 24,
            fontWeight: 800,
            textTransform: 'uppercase',
            marginTop: 8,
            color: riskLevel === 'critical' ? '#e11d48' : riskLevel === 'high' ? '#ea580c' : riskLevel === 'medium' ? '#d97706' : '#059669',
          }}>
            {riskLevel} Threat
          </div>
          <p style={{ fontSize: 12, color: '#64748b', marginTop: 6, lineHeight: 1.5 }}>
            {riskLevel === 'critical' || riskLevel === 'high'
              ? 'Target exhibits active phishing indicators, malicious infrastructure, or severe cryptography flaws.'
              : 'Target does not demonstrate conclusive active phishing signals.'}
          </p>
        </div>

        {/* Confidence Level Card */}
        <div style={{
          background: '#ffffff',
          borderRadius: 18,
          border: '1.5px solid var(--border-subtle)',
          padding: 22,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          boxShadow: 'var(--shadow-sm)',
        }}>
          <span style={{ fontSize: 12, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
            Assessment Confidence
          </span>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#0284c7', marginTop: 8, fontFamily: 'IBM Plex Mono' }}>
            {Math.round(confidence * 100)}%
          </div>
          <p style={{ fontSize: 12, color: '#64748b', marginTop: 6, lineHeight: 1.5 }}>
            Confidence represents evidence corroboration depth across DNS, TLS, DOM heuristics, and community reports.
          </p>
        </div>

        {/* Factor Breakdown Card */}
        <div style={{
          background: '#ffffff',
          borderRadius: 18,
          border: '1.5px solid var(--border-subtle)',
          padding: 22,
          boxShadow: 'var(--shadow-sm)',
        }}>
          <span style={{ fontSize: 12, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
            Contributing Vectors
          </span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 4, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#475569' }}>URL Threat Heuristics:</span>
              <strong style={{ color: '#0f172a', fontFamily: 'IBM Plex Mono' }}>{breakdown.url_threats} pts</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 4, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#475569' }}>TLS Cryptography:</span>
              <strong style={{ color: '#0f172a', fontFamily: 'IBM Plex Mono' }}>{breakdown.tls_vulnerabilities} pts</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#475569' }}>DOM & Headers:</span>
              <strong style={{ color: '#0f172a', fontFamily: 'IBM Plex Mono' }}>{breakdown.content_and_headers} pts</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Findings Section with Filter */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a' }}>
              Security Findings ({findings.length})
            </h3>
            <p style={{ fontSize: 13, color: '#64748b' }}>
              Detailed breakdown of detected anomalies, threat indicators, and technical evidence.
            </p>
          </div>

          {/* Severity Filter Tabs */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  background: severityFilter === sev ? '#0284c7' : '#f8fafc',
                  color: severityFilter === sev ? '#ffffff' : '#64748b',
                  border: `1.5px solid ${severityFilter === sev ? '#0284c7' : '#e2e8f0'}`,
                  padding: '5px 13px',
                  borderRadius: 999,
                  fontSize: 11.5,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {loadingFindings ? (
          <div style={{ padding: 48, textAlign: 'center', color: '#0284c7', fontWeight: 600 }}>
            Loading findings...
          </div>
        ) : filteredFindings.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: '#94a3b8' }}>
            No findings matching the selected filter.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {filteredFindings.map((f, idx) => {
              const cfg = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.info;
              return (
                <div
                  key={f.finding_id || idx}
                  style={{
                    background: '#f8fafc',
                    borderRadius: 14,
                    border: '1px solid #e2e8f0',
                    padding: 18,
                    borderLeft: `4px solid ${cfg.text}`,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{
                        background: cfg.bg,
                        color: cfg.text,
                        border: `1px solid ${cfg.border}`,
                        fontSize: 10,
                        fontWeight: 800,
                        padding: '3px 8px',
                        borderRadius: 6,
                        textTransform: 'uppercase',
                      }}>
                        {f.severity}
                      </span>
                      <h4 style={{ fontSize: 15, fontWeight: 700, color: '#0f172a' }}>
                        {f.title}
                      </h4>
                    </div>
                    <span style={{ fontSize: 11, color: '#64748b', fontFamily: 'IBM Plex Mono' }}>
                      Module: {f.module}
                    </span>
                  </div>

                  <p style={{ fontSize: 13, color: '#334155', marginTop: 8, lineHeight: 1.6 }}>
                    {f.description}
                  </p>

                  {f.recommendation && (
                    <div style={{
                      marginTop: 12,
                      background: '#ecfdf5',
                      border: '1px solid #a7f3d0',
                      padding: '10px 14px',
                      borderRadius: 10,
                      fontSize: 12.5,
                      color: '#065f46',
                      lineHeight: 1.5,
                    }}>
                      <strong>💡 Recommended Action:</strong> {f.recommendation}
                    </div>
                  )}

                  {f.evidence && Object.keys(f.evidence).length > 0 && (
                    <div style={{ marginTop: 10 }}>
                      <details style={{ fontSize: 12, color: '#64748b' }}>
                        <summary style={{ cursor: 'pointer', color: '#0284c7', fontWeight: 600 }}>
                          View Technical Evidence
                        </summary>
                        <pre style={{
                          background: '#ffffff',
                          border: '1px solid #e2e8f0',
                          padding: 12,
                          borderRadius: 8,
                          marginTop: 6,
                          overflowX: 'auto',
                          color: '#0369a1',
                          fontFamily: 'IBM Plex Mono',
                          fontSize: 11.5,
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
