import React, { useState, useEffect } from 'react';

export default function FlightRecorder({ hostname }) {
  const [targetDomain, setTargetDomain] = useState(hostname || '');
  const [historyData, setHistoryData] = useState(null);
  const [comparisonData, setComparisonData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (hostname) {
      setTargetDomain(hostname);
      loadDomainHistory(hostname);
    }
  }, [hostname]);

  async function loadDomainHistory(domain) {
    if (!domain) return;
    setLoading(true);
    setError(null);

    try {
      // 1. Fetch domain history
      const histRes = await fetch(`/api/domains/${domain}/history`);
      if (!histRes.ok) throw new Error('Could not fetch domain history');
      const hist = await histRes.json();
      setHistoryData(hist);

      // 2. Fetch comparison if >= 2 scans exist
      if (hist.total >= 2) {
        const compRes = await fetch(`/api/domains/${domain}/compare`);
        if (compRes.ok) {
          const comp = await compRes.json();
          setComparisonData(comp);
        }
      } else {
        setComparisonData(null);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function handleSearch(e) {
    e.preventDefault();
    if (targetDomain.trim()) {
      loadDomainHistory(targetDomain.trim());
    }
  }

  const scans = historyData?.scans || [];
  const snapshots = historyData?.snapshots || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1050, margin: '0 auto' }}>
      {/* Header & Domain Search Bar */}
      <div style={{
        background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <span style={{ fontSize: 12, color: '#a78bfa', fontWeight: 700, textTransform: 'uppercase' }}>
              ⏱️ Phishing Flight Recorder
            </span>
            <h2 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', marginTop: 4 }}>
              Historical Snapshot Timeline & Infrastructure Drift
            </h2>
            <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
              Preserves point-in-time security states across recurring scans to detect malicious modification.
            </p>
          </div>

          <form onSubmit={handleSearch} style={{ display: 'flex', gap: 10 }}>
            <input
              type="text"
              placeholder="Domain to inspect..."
              value={targetDomain}
              onChange={e => setTargetDomain(e.target.value)}
              style={{
                background: '#0a0d14', color: '#f8fafc', border: '1px solid #23304c',
                padding: '8px 14px', borderRadius: 8, fontSize: 13, fontFamily: 'JetBrains Mono',
              }}
            />
            <button
              type="submit"
              disabled={loading}
              style={{
                background: '#6366f1', color: '#fff', border: 'none',
                padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: 'pointer',
              }}
            >
              {loading ? 'Querying...' : 'Load Timeline'}
            </button>
          </form>
        </div>
      </div>

      {error && (
        <div style={{ background: 'rgba(244, 63, 94, 0.15)', color: '#fda4af', padding: 14, borderRadius: 10 }}>
          {error}
        </div>
      )}

      {/* Comparison Delta View (when >= 2 scans available) */}
      {comparisonData && comparisonData.consecutive_comparisons?.length > 0 && (
        <div style={{ background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
              Consecutive Scan Delta Analysis
            </h3>
            <span style={{
              fontSize: 11, padding: '3px 10px', borderRadius: 6, fontWeight: 700,
              background: 'rgba(99, 102, 241, 0.2)', color: '#a5b4fc',
            }}>
              {comparisonData.scan_count} Recorded Observations
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 18 }}>
            {comparisonData.consecutive_comparisons.map((pair, idx) => {
              const delta = pair.risk_score_delta;
              const isEscalated = delta > 0;
              return (
                <div
                  key={idx}
                  style={{
                    background: '#0c101c', borderRadius: 10, border: '1px solid #23304c', padding: 18,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                    <div>
                      <h4 style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc' }}>
                        Delta: Scan {pair.previous_scan_id.slice(0, 8)}... → {pair.latest_scan_id.slice(0, 8)}...
                      </h4>
                      <p style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
                        Observed from {new Date(pair.previous_timestamp).toLocaleDateString()} to {new Date(pair.latest_timestamp).toLocaleDateString()}
                      </p>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{
                        padding: '4px 12px', borderRadius: 6, fontSize: 12, fontWeight: 800,
                        background: isEscalated ? 'rgba(244, 63, 94, 0.15)' : delta < 0 ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                        color: isEscalated ? '#fda4af' : delta < 0 ? '#6ee7b7' : '#cbd5e1',
                      }}>
                        Score Delta: {delta > 0 ? `+${delta}` : delta} pts ({pair.risk_trend})
                      </span>
                    </div>
                  </div>

                  {/* Drift Indicator Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginTop: 16 }}>
                    {/* New Findings */}
                    <div style={{ background: '#151d30', padding: 12, borderRadius: 8, border: '1px solid #23304c' }}>
                      <span style={{ fontSize: 11, color: '#fda4af', fontWeight: 700, textTransform: 'uppercase' }}>
                        + Newly Emerged Findings ({pair.new_findings?.length || 0})
                      </span>
                      <ul style={{ marginTop: 6, fontSize: 11, color: '#cbd5e1', paddingLeft: 16 }}>
                        {pair.new_findings?.length > 0 ? (
                          pair.new_findings.map((f, i) => <li key={i}>{f}</li>)
                        ) : (
                          <li style={{ color: '#64748b' }}>None</li>
                        )}
                      </ul>
                    </div>

                    {/* Resolved Findings */}
                    <div style={{ background: '#151d30', padding: 12, borderRadius: 8, border: '1px solid #23304c' }}>
                      <span style={{ fontSize: 11, color: '#6ee7b7', fontWeight: 700, textTransform: 'uppercase' }}>
                        - Resolved Findings ({pair.resolved_findings?.length || 0})
                      </span>
                      <ul style={{ marginTop: 6, fontSize: 11, color: '#cbd5e1', paddingLeft: 16 }}>
                        {pair.resolved_findings?.length > 0 ? (
                          pair.resolved_findings.map((f, i) => <li key={i}>{f}</li>)
                        ) : (
                          <li style={{ color: '#64748b' }}>None</li>
                        )}
                      </ul>
                    </div>

                    {/* TLS & Header Changes */}
                    <div style={{ background: '#151d30', padding: 12, borderRadius: 8, border: '1px solid #23304c' }}>
                      <span style={{ fontSize: 11, color: '#38bdf8', fontWeight: 700, textTransform: 'uppercase' }}>
                        Infrastructure Shifts
                      </span>
                      <div style={{ marginTop: 6, fontSize: 11, color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: 4 }}>
                        <div>TLS Changed: <strong>{pair.tls_changed ? '⚠️ YES' : 'No'}</strong></div>
                        <div>Headers Stripped: <strong>{pair.headers_removed?.join(', ') || 'None'}</strong></div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Historical Observation Timeline */}
      <div style={{ background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc', marginBottom: 16 }}>
          Point-in-Time Scan Snapshots Timeline
        </h3>

        {scans.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
            No recorded observations found for this hostname. Run a scan first.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {scans.map((scan, i) => (
              <div
                key={scan.scan_id || i}
                style={{
                  background: '#0c101c', borderRadius: 10, border: '1px solid #23304c', padding: 16,
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12,
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{
                      fontSize: 11, fontWeight: 800, padding: '2px 8px', borderRadius: 4,
                      background: (scan.risk_score || 0) >= 50 ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                      color: (scan.risk_score || 0) >= 50 ? '#fda4af' : '#6ee7b7',
                    }}>
                      Score: {(scan.risk_score || 0).toFixed(1)}/100
                    </span>
                    <h4 style={{ fontSize: 13, fontWeight: 600, color: '#f8fafc', fontFamily: 'JetBrains Mono' }}>
                      {scan.scan_id}
                    </h4>
                  </div>
                  <p style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>
                    Recorded at: {new Date(scan.created_at).toLocaleString()} • Duration: {scan.duration_ms}ms
                  </p>
                </div>

                <div style={{ fontSize: 12, color: '#94a3b8' }}>
                  Modules: {scan.module_results?.length || 0} • Status: {scan.status}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
