import React, { useState, useEffect } from 'react';

export default function FlightRecorder({ hostname, onNavigate }) {
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
      const histRes = await fetch(`/api/domains/${domain}/history`);
      if (!histRes.ok) throw new Error('Could not fetch domain history');
      const hist = await histRes.json();
      setHistoryData(hist);

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1100, margin: '0 auto' }}>
      {/* Header & Domain Search Bar */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              ⏱️ Phishing Flight Recorder
            </span>
            <h2 style={{ fontSize: 24, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
              Historical Snapshot Timeline & Infrastructure Drift
            </h2>
            <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
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
                background: '#f8fafc',
                color: '#0f172a',
                border: '1.5px solid #cbd5e1',
                padding: '9px 16px',
                borderRadius: 999,
                fontSize: 13,
                fontFamily: 'IBM Plex Mono',
                outline: 'none',
                width: 220,
              }}
            />
            <button
              type="submit"
              disabled={loading}
              style={{
                background: 'linear-gradient(135deg, #0284c7, #0ea5e9)',
                color: '#ffffff',
                border: 'none',
                padding: '10px 20px',
                borderRadius: 999,
                fontSize: 13.5,
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: '0 3px 10px rgba(2, 132, 199, 0.28)',
              }}
            >
              {loading ? 'Querying...' : 'Load Timeline'}
            </button>
          </form>
        </div>
      </div>

      {error && (
        <div style={{
          background: '#fff1f2',
          border: '1px solid #fecdd3',
          color: '#e11d48',
          padding: 16,
          borderRadius: 14,
          fontSize: 13,
          fontWeight: 600,
        }}>
          ⚠️ {error}
        </div>
      )}

      {/* Comparison Delta View (when >= 2 scans available) */}
      {comparisonData && comparisonData.consecutive_comparisons?.length > 0 && (
        <div style={{
          background: '#ffffff',
          borderRadius: 20,
          border: '1.5px solid var(--border-subtle)',
          padding: '26px 30px',
          boxShadow: 'var(--shadow-sm)',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                Drift Evaluation
              </span>
              <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                Consecutive Scan Delta Analysis
              </h3>
            </div>
            <span style={{
              fontSize: 12,
              padding: '4px 12px',
              borderRadius: 999,
              fontWeight: 700,
              background: '#e0f2fe',
              color: '#0369a1',
              fontFamily: 'IBM Plex Mono',
            }}>
              {comparisonData.scan_count} Recorded Observations
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 20 }}>
            {comparisonData.consecutive_comparisons.map((pair, idx) => {
              const delta = pair.risk_score_delta;
              const isEscalated = delta > 0;
              const deltaBg = isEscalated ? '#fff1f2' : delta < 0 ? '#ecfdf5' : '#f1f5f9';
              const deltaColor = isEscalated ? '#e11d48' : delta < 0 ? '#059669' : '#475569';
              const deltaBorder = isEscalated ? '#fecdd3' : delta < 0 ? '#a7f3d0' : '#cbd5e1';

              return (
                <div
                  key={idx}
                  style={{
                    background: '#f8fafc',
                    borderRadius: 16,
                    border: '1px solid #e2e8f0',
                    padding: 20,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                    <div>
                      <h4 style={{ fontSize: 14, fontWeight: 700, color: '#0f172a', fontFamily: 'IBM Plex Mono' }}>
                        Delta: Scan {pair.previous_scan_id.slice(0, 8)}... → {pair.latest_scan_id.slice(0, 8)}...
                      </h4>
                      <p style={{ fontSize: 12, color: '#64748b', marginTop: 3 }}>
                        Observed from {new Date(pair.previous_timestamp).toLocaleDateString()} to {new Date(pair.latest_timestamp).toLocaleDateString()}
                      </p>
                    </div>

                    <span style={{
                      padding: '4px 14px',
                      borderRadius: 999,
                      fontSize: 12,
                      fontWeight: 800,
                      background: deltaBg,
                      color: deltaColor,
                      border: `1px solid ${deltaBorder}`,
                      fontFamily: 'IBM Plex Mono',
                    }}>
                      Score Delta: {delta > 0 ? `+${delta}` : delta} pts ({pair.risk_trend})
                    </span>
                  </div>

                  {/* Drift Indicator Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginTop: 16 }}>
                    {/* New Findings */}
                    <div style={{ background: '#ffffff', padding: 14, borderRadius: 12, border: '1px solid #e2e8f0' }}>
                      <span style={{ fontSize: 11, color: '#e11d48', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                        + Newly Emerged Findings ({pair.new_findings?.length || 0})
                      </span>
                      <ul style={{ marginTop: 8, fontSize: 12, color: '#334155', paddingLeft: 18 }}>
                        {pair.new_findings?.length > 0 ? (
                          pair.new_findings.map((f, i) => <li key={i}>{f}</li>)
                        ) : (
                          <li style={{ color: '#94a3b8' }}>None</li>
                        )}
                      </ul>
                    </div>

                    {/* Resolved Findings */}
                    <div style={{ background: '#ffffff', padding: 14, borderRadius: 12, border: '1px solid #e2e8f0' }}>
                      <span style={{ fontSize: 11, color: '#059669', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                        - Resolved Findings ({pair.resolved_findings?.length || 0})
                      </span>
                      <ul style={{ marginTop: 8, fontSize: 12, color: '#334155', paddingLeft: 18 }}>
                        {pair.resolved_findings?.length > 0 ? (
                          pair.resolved_findings.map((f, i) => <li key={i}>{f}</li>)
                        ) : (
                          <li style={{ color: '#94a3b8' }}>None</li>
                        )}
                      </ul>
                    </div>

                    {/* TLS & Header Changes */}
                    <div style={{ background: '#ffffff', padding: 14, borderRadius: 12, border: '1px solid #e2e8f0' }}>
                      <span style={{ fontSize: 11, color: '#0284c7', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                        Infrastructure Shifts
                      </span>
                      <div style={{ marginTop: 8, fontSize: 12, color: '#334155', display: 'flex', flexDirection: 'column', gap: 4 }}>
                        <div>TLS Changed: <strong style={{ color: pair.tls_changed ? '#e11d48' : '#059669' }}>{pair.tls_changed ? '⚠️ YES' : 'No'}</strong></div>
                        <div>Headers Stripped: <strong style={{ color: pair.headers_removed?.length ? '#e11d48' : '#0f172a' }}>{pair.headers_removed?.join(', ') || 'None'}</strong></div>
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
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginBottom: 16 }}>
          Point-in-Time Scan Snapshots Timeline
        </h3>

        {scans.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: '#94a3b8' }}>
            No recorded observations found for this hostname. Enter a domain above or run a scan.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {scans.map((scan, i) => {
              const score = scan.risk_score || 0;
              const isHigh = score >= 50;

              return (
                <div
                  key={scan.scan_id || i}
                  style={{
                    background: '#f8fafc',
                    borderRadius: 14,
                    border: '1px solid #e2e8f0',
                    padding: 16,
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: 12,
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{
                        fontSize: 11,
                        fontWeight: 800,
                        padding: '3px 9px',
                        borderRadius: 999,
                        background: isHigh ? '#fff1f2' : '#ecfdf5',
                        color: isHigh ? '#e11d48' : '#059669',
                        border: `1px solid ${isHigh ? '#fecdd3' : '#a7f3d0'}`,
                        fontFamily: 'IBM Plex Mono',
                      }}>
                        Score: {score.toFixed(1)}/100
                      </span>
                      <h4 style={{ fontSize: 13, fontWeight: 700, color: '#0f172a', fontFamily: 'IBM Plex Mono' }}>
                        {scan.scan_id}
                      </h4>
                    </div>
                    <p style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>
                      Recorded at: {new Date(scan.created_at).toLocaleString()} • Duration: {scan.duration_ms}ms
                    </p>
                  </div>

                  <div style={{ fontSize: 12, color: '#64748b', fontFamily: 'IBM Plex Mono' }}>
                    Modules: {scan.module_results?.length || 0} • Status: <span style={{ color: '#0284c7', fontWeight: 600 }}>{scan.status}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
