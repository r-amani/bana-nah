import React, { useState, useEffect } from 'react';

const AVAILABLE_MODULES = [
  {
    id: 'url_detection',
    shortLabel: 'Lexical',
    label: 'URL Lexical & Homograph Threat Detection',
    desc: 'Entropy, typosquatting, Punycode, high-risk TLDs',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M5 7V5h14v2"></path>
        <path d="M12 5v14"></path>
        <path d="M9 19h6"></path>
      </svg>
    ),
  },
  {
    id: 'tls_validation',
    shortLabel: 'TLS',
    label: 'TLS Certificate Validation',
    desc: 'Expiry, SAN verification, self-signed detection, CA analysis',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="4.5" y="10.5" width="15" height="10" rx="2.5"></rect>
        <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"></path>
      </svg>
    ),
  },
  {
    id: 'security_assessment',
    shortLabel: 'Security',
    label: 'Website Security Assessment',
    desc: 'Security headers (CSP/HSTS), password form audits, redirect tracking',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 3 5 6v5.5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6z"></path>
        <path d="m9 12 2.2 2.2L15.5 10"></path>
      </svg>
    ),
  },
  {
    id: 'community_intelligence',
    shortLabel: 'Community',
    label: 'Community Threat Intelligence',
    desc: 'Deduplicated crowd reports & optional external intelligence feeds',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="9" cy="8.5" r="3.2"></circle>
        <path d="M3.5 19a5.5 5.5 0 0 1 11 0"></path>
        <path d="M16 5.6a3.2 3.2 0 0 1 0 5.8M18 14.2a5.5 5.5 0 0 1 2.5 4.8"></path>
      </svg>
    ),
  },
  {
    id: 'risk_scoring',
    shortLabel: 'Risk score',
    label: 'Explainable Risk Scoring Engine',
    desc: 'Multi-factor severity aggregation with remediation guidance',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4.5 16a8 8 0 1 1 15 0"></path>
        <path d="m12 15 3.5-4"></path>
        <circle cx="12" cy="15" r="1.2"></circle>
      </svg>
    ),
  },
  {
    id: 'flight_recorder',
    shortLabel: 'Recorder',
    label: 'Phishing Flight Recorder',
    desc: 'Historical snapshot capture & infrastructure drift deltas',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1L3.5 8.5"></path>
        <path d="M3.5 4v4.5H8"></path>
        <path d="M12 8v4.2l2.8 1.8"></path>
      </svg>
    ),
  },
  {
    id: 'attack_fingerprint',
    shortLabel: 'Family',
    label: 'Attack Family Fingerprinting',
    desc: 'Evidence-based campaign & shared infrastructure correlation',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 4.5a7.5 7.5 0 0 0-7.5 7.5v1.5"></path>
        <path d="M12 4.5a7.5 7.5 0 0 1 7.5 7.5c0 2.3-.4 4.2-1.2 6"></path>
        <path d="M12 8.5A3.5 3.5 0 0 0 8.5 12c0 2.6-.6 4.6-1.6 6.3"></path>
        <path d="M12 8.5a3.5 3.5 0 0 1 3.5 3.5c0 2.6-.5 4.5-1.4 6.2"></path>
        <path d="M12 12c0 2.8-.4 5-1.2 6.8"></path>
      </svg>
    ),
  },
  {
    id: 'graph_enrichment',
    shortLabel: 'Graph',
    label: 'Investigation Graph Enrichment',
    desc: 'Topology synthesis and entity-relationship resolution',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="6" cy="12" r="2.5"></circle>
        <circle cx="18" cy="6" r="2.5"></circle>
        <circle cx="18" cy="18" r="2.5"></circle>
        <path d="m8.2 10.8 7.6-3.6M8.2 13.2l7.6 3.6"></path>
      </svg>
    ),
  },
];

export default function ScannerHome({ onScanComplete, initialUrl = '', onNavigate }) {
  const [targetUrl, setTargetUrl] = useState(initialUrl);
  const [selectedModules, setSelectedModules] = useState(AVAILABLE_MODULES.map(m => m.id));
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [recentScans, setRecentScans] = useState([]);

  useEffect(() => {
    fetchRecentScans();
  }, []);

  async function fetchRecentScans() {
    try {
      const res = await fetch('/api/scans?limit=5');
      if (res.ok) {
        const data = await res.json();
        setRecentScans(data);
      }
    } catch (e) {
      console.warn('Could not fetch recent scans:', e);
    }
  }

  function toggleModule(id) {
    if (selectedModules.includes(id)) {
      setSelectedModules(selectedModules.filter(m => m !== id));
    } else {
      setSelectedModules([...selectedModules, id]);
    }
  }

  function selectAll() {
    setSelectedModules(AVAILABLE_MODULES.map(m => m.id));
  }

  function clearAll() {
    setSelectedModules([]);
  }

  async function handleScanSubmit(e) {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    setError(null);
    setScanning(true);

    try {
      let formatted = targetUrl.trim();
      if (!formatted.startsWith('http://') && !formatted.startsWith('https://')) {
        formatted = 'https://' + formatted;
      }

      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: formatted,
          modules: selectedModules,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        let message = 'Scan request failed';
        if (typeof errData.detail === 'string') {
          message = errData.detail;
        } else if (Array.isArray(errData.detail)) {
          message = errData.detail
            .map(d => `${d.loc ? d.loc.filter(l => l !== 'body').join('.') + ': ' : ''}${d.msg}`)
            .join('; ');
        }
        throw new Error(message || `Scan request failed with status ${res.status}`);
      }

      const scanResult = await res.json();
      onScanComplete(scanResult);
      fetchRecentScans();
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  }

  return (
    <div style={{
      maxWidth: 1240,
      margin: '0 auto',
      display: 'flex',
      alignItems: 'flex-start',
      justifyContent: 'center',
      gap: 36,
      flexWrap: 'wrap',
    }}>
      {/* Main Scanner Section */}
      <section style={{
        position: 'relative',
        isolation: 'isolate',
        flex: '1 1 760px',
        maxWidth: 820,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
      }}>
        {/* Decorative concentric radar circles in background */}
        <svg
          aria-hidden="true"
          width="900"
          height="560"
          viewBox="0 0 900 560"
          fill="none"
          stroke="#0284c7"
          strokeWidth="1.5"
          style={{
            position: 'absolute',
            left: '50%',
            top: 200,
            transform: 'translate(-50%, -50%)',
            zIndex: -1,
            pointerEvents: 'none',
          }}
        >
          <circle cx="450" cy="280" r="140" strokeOpacity="0.12"></circle>
          <circle cx="450" cy="280" r="230" strokeOpacity="0.08"></circle>
          <circle cx="450" cy="280" r="320" strokeOpacity="0.05"></circle>
          <circle cx="450" cy="280" r="410" strokeOpacity="0.03"></circle>
        </svg>

        {/* Category Pill Tag */}
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          padding: '6px 16px',
          borderRadius: 999,
          background: 'rgba(2, 132, 199, 0.08)',
          border: '1px solid rgba(2, 132, 199, 0.22)',
          color: '#0284c7',
          fontSize: 12,
          fontWeight: 700,
          letterSpacing: '.07em',
          textTransform: 'uppercase',
        }}>
          Multi-stage digital threat investigation
        </div>

        {/* Hero Headline */}
        <h1 style={{
          margin: '18px 0 10px',
          fontSize: 42,
          fontWeight: 800,
          lineHeight: 1.15,
          letterSpacing: '-0.025em',
          color: '#0f172a',
        }}>
          Investigate any suspicious link
        </h1>

        {/* Hero Subtitle */}
        <p style={{
          margin: '0 auto',
          maxWidth: 580,
          fontSize: 16,
          lineHeight: 1.6,
          color: '#64748b',
        }}>
          Paste a URL and run up to eight checks. Get an explainable risk verdict with technical evidence behind it.
        </p>

        {/* URL Pill Input Form */}
        <form onSubmit={handleScanSubmit} style={{ width: '100%', maxWidth: 720, marginTop: 28 }}>
          <div className="pill-input-box">
            <label className="sr-only" htmlFor="url-input">URL to investigate</label>
            <span aria-hidden="true" style={{ display: 'flex', color: '#94a3b8' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"></path>
                <path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"></path>
              </svg>
            </span>

            <input
              id="url-input"
              type="text"
              placeholder="https://paypa1-update.xyz/login"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              disabled={scanning}
              style={{
                flex: '1 1 auto',
                minWidth: 0,
                height: 48,
                border: 0,
                outline: 0,
                background: 'transparent',
                fontFamily: 'IBM Plex Mono, monospace',
                fontSize: 15,
                fontWeight: 500,
                color: '#0f172a',
              }}
            />

            <button
              className="pill-scan-btn"
              type="submit"
              disabled={scanning || !targetUrl.trim() || selectedModules.length === 0}
              aria-label="Scan URL"
              title={scanning ? 'Scanning...' : 'Scan URL'}
            >
              {scanning ? (
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ animation: 'spin 1s linear infinite' }}>
                  <path d="M21 12a9 9 0 1 1-6.219-8.56"></path>
                </svg>
              ) : (
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M5 12h14"></path>
                  <path d="m13 6 6 6-6 6"></path>
                </svg>
              )}
            </button>
          </div>
        </form>

        {/* Error Alert */}
        {error && (
          <div style={{
            width: '100%',
            maxWidth: 720,
            marginTop: 14,
            padding: '12px 18px',
            background: '#fff1f2',
            border: '1px solid #fecdd3',
            borderRadius: 12,
            color: '#e11d48',
            fontSize: 13,
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            textAlign: 'left',
          }}>
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {/* Checks To Run Controls Header */}
        <div style={{
          width: '100%',
          maxWidth: 760,
          marginTop: 32,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: '#64748b' }}>
              Checks to run
            </span>
            <span style={{
              padding: '3px 10px',
              borderRadius: 999,
              background: '#e0f2fe',
              color: '#0369a1',
              fontFamily: 'IBM Plex Mono, monospace',
              fontSize: 12,
              fontWeight: 600,
            }}>
              {selectedModules.length} of {AVAILABLE_MODULES.length}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              className="round-btn"
              type="button"
              onClick={selectAll}
              aria-label="Select all checks"
              title="Select all"
            >
              <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="m3.5 12.5 4 4 7-8"></path>
                <path d="m12 15.5 1 1 7.5-9"></path>
              </svg>
            </button>
            <button
              className="round-btn"
              type="button"
              onClick={clearAll}
              aria-label="Clear all checks"
              title="Clear all"
            >
              <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M6 6l12 12"></path>
                <path d="M18 6 6 18"></path>
              </svg>
            </button>
          </div>
        </div>

        {/* 8 Circular Check Buttons Row */}
        <div style={{
          width: '100%',
          maxWidth: 780,
          marginTop: 12,
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 6,
        }}>
          {AVAILABLE_MODULES.map(mod => {
            const isChecked = selectedModules.includes(mod.id);
            return (
              <button
                key={mod.id}
                className="chk-btn"
                type="button"
                aria-pressed={isChecked ? 'true' : 'false'}
                onClick={() => toggleModule(mod.id)}
                title={mod.label}
              >
                <span className="chk-circle">
                  {mod.icon}
                  <span className="chk-badge" aria-hidden="true">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round">
                      <path d="m5 12.5 4.5 4.5L19 7.5"></path>
                    </svg>
                  </span>
                </span>
                <span>{mod.shortLabel}</span>
              </button>
            );
          })}
        </div>

        {/* Investigation Tools Divider */}
        <div style={{
          width: '100%',
          maxWidth: 760,
          marginTop: 36,
          display: 'flex',
          alignItems: 'center',
          gap: 16,
        }}>
          <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: '#64748b' }}>
            Investigation tools
          </span>
          <span aria-hidden="true" style={{ flex: '1 1 auto', height: 1, background: '#e2e8f0' }} />
        </div>

        {/* Investigation Tools Launcher Row */}
        <div style={{
          width: '100%',
          maxWidth: 780,
          marginTop: 16,
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 8,
        }}>
          <button
            className="tool-launcher"
            type="button"
            onClick={() => onNavigate && onNavigate('report')}
            title="Verdicts, evidence and remediation steps"
          >
            <span className="tool-circle">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"></path>
                <path d="M14 3v5h5"></path>
                <path d="M9 13h6M9 17h6"></path>
              </svg>
            </span>
            <span className="tool-label">Scan Report</span>
          </button>

          <button
            className="tool-launcher"
            type="button"
            onClick={() => onNavigate && onNavigate('certificate')}
            title="Expiry, SAN checks, self-signed detection"
          >
            <span className="tool-circle">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <rect x="4.5" y="10.5" width="15" height="10" rx="2.5"></rect>
                <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"></path>
              </svg>
            </span>
            <span className="tool-label">TLS Certificate</span>
          </button>

          <button
            className="tool-launcher"
            type="button"
            onClick={() => onNavigate && onNavigate('assessment')}
            title="Headers, password forms, redirect tracking"
          >
            <span className="tool-circle">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 3 5 6v5.5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6z"></path>
                <path d="m9 12 2.2 2.2L15.5 10"></path>
              </svg>
            </span>
            <span className="tool-label">Security Assessment</span>
          </button>

          <button
            className="tool-launcher"
            type="button"
            onClick={() => onNavigate && onNavigate('flight_recorder')}
            title="Snapshots and infrastructure drift over time"
          >
            <span className="tool-circle">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1L3.5 8.5"></path>
                <path d="M3.5 4v4.5H8"></path>
                <path d="M12 8v4.2l2.8 1.8"></path>
              </svg>
            </span>
            <span className="tool-label">Flight Recorder</span>
          </button>

          <button
            className="tool-launcher"
            type="button"
            onClick={() => onNavigate && onNavigate('community')}
            title="Crowd reports and external intelligence"
          >
            <span className="tool-circle">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="9" cy="8.5" r="3.2"></circle>
                <path d="M3.5 19a5.5 5.5 0 0 1 11 0"></path>
                <path d="M16 5.6a3.2 3.2 0 0 1 0 5.8M18 14.2a5.5 5.5 0 0 1 2.5 4.8"></path>
              </svg>
            </span>
            <span className="tool-label">Community Reports</span>
          </button>

          <button
            className="tool-launcher"
            type="button"
            onClick={() => onNavigate && onNavigate('graph')}
            title="Entities, infrastructure and attack families"
          >
            <span className="tool-circle">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="6" cy="12" r="2.5"></circle>
                <circle cx="18" cy="6" r="2.5"></circle>
                <circle cx="18" cy="18" r="2.5"></circle>
                <path d="m8.2 10.8 7.6-3.6M8.2 13.2l7.6 3.6"></path>
              </svg>
            </span>
            <span className="tool-label">Investigation Graph</span>
          </button>
        </div>
      </section>

      {/* Right Aside: Recent Investigations */}
      <aside style={{
        flex: '0 0 300px',
        background: '#ffffff',
        border: '1.5px solid var(--border-subtle)',
        borderRadius: 20,
        padding: '18px 16px',
        boxShadow: 'var(--shadow-sm)',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 4px 6px' }}>
          <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: '#0f172a' }}>
            Recent investigations
          </h2>
          <button
            onClick={() => onNavigate && onNavigate('dashboard')}
            className="round-btn"
            style={{ width: 32, height: 32 }}
            title="View Dashboard History"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M7 17 17 7"></path>
              <path d="M8 7h9v9"></path>
            </svg>
          </button>
        </div>

        {recentScans.length > 0 ? (
          recentScans.map(scan => {
            const score = scan.risk_score || 0;
            const isHigh = score >= 50;
            const isSuspicious = score >= 25 && score < 50;
            const dotColor = isHigh ? '#e11d48' : isSuspicious ? '#d97706' : '#059669';
            const riskLabel = isHigh ? 'High risk' : isSuspicious ? 'Suspicious' : 'Looks safe';
            const labelColor = isHigh ? '#e11d48' : isSuspicious ? '#b45309' : '#059669';

            return (
              <div
                key={scan.scan_id}
                onClick={() => onScanComplete(scan)}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 12,
                  padding: '10px 12px',
                  borderRadius: 12,
                  cursor: 'pointer',
                  background: '#f8fafc',
                  border: '1px solid #f1f5f9',
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.background = '#f0f7ff';
                  e.currentTarget.style.borderColor = '#bae6fd';
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.background = '#f8fafc';
                  e.currentTarget.style.borderColor = '#f1f5f9';
                }}
              >
                <span style={{
                  flexShrink: 0,
                  width: 9,
                  height: 9,
                  marginTop: 6,
                  borderRadius: '50%',
                  background: dotColor,
                }} />
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0, flex: 1 }}>
                  <span style={{
                    fontFamily: 'IBM Plex Mono, monospace',
                    fontSize: 13,
                    fontWeight: 600,
                    color: '#0f172a',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}>
                    {scan.hostname || scan.target_url}
                  </span>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: labelColor }}>
                      {riskLabel}
                    </span>
                    <span style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'IBM Plex Mono' }}>
                      {score.toFixed(0)}/100
                    </span>
                  </div>
                </div>
              </div>
            );
          })
        ) : (
          /* Sample mockup indicators matching Main.dc.html if no scans yet */
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 12,
                padding: '10px 12px',
                borderRadius: 12,
                background: '#f8fafc',
                border: '1px solid #f1f5f9',
              }}
            >
              <span style={{ flexShrink: 0, width: 9, height: 9, marginTop: 6, borderRadius: '50%', background: '#e11d48' }} />
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 13, fontWeight: 600, color: '#0f172a' }}>
                  paypa1-update.xyz
                </span>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#e11d48' }}>High risk</span>
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 12,
                padding: '10px 12px',
                borderRadius: 12,
                background: '#f8fafc',
                border: '1px solid #f1f5f9',
              }}
            >
              <span style={{ flexShrink: 0, width: 9, height: 9, marginTop: 6, borderRadius: '50%', background: '#d97706' }} />
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 13, fontWeight: 600, color: '#0f172a' }}>
                  account-verify-portal.top
                </span>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#b45309' }}>Suspicious</span>
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 12,
                padding: '10px 12px',
                borderRadius: 12,
                background: '#f8fafc',
                border: '1px solid #f1f5f9',
              }}
            >
              <span style={{ flexShrink: 0, width: 9, height: 9, marginTop: 6, borderRadius: '50%', background: '#059669' }} />
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 13, fontWeight: 600, color: '#0f172a' }}>
                  example.org
                </span>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#059669' }}>Looks safe</span>
              </div>
            </div>
            <div style={{ padding: '6px 8px 0', fontSize: 11, fontFamily: 'IBM Plex Mono', letterSpacing: '.06em', textTransform: 'uppercase', color: '#94a3b8' }}>
              Sample reference data
            </div>
          </>
        )}
      </aside>
    </div>
  );
}
