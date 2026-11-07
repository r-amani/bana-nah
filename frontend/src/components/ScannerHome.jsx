import React, { useState, useEffect } from 'react';

const AVAILABLE_MODULES = [
  { id: 'url_detection', label: 'URL Lexical & Homograph Threat Detection', desc: 'Entropy, typosquatting, Punycode, high-risk TLDs' },
  { id: 'tls_validation', label: 'TLS Certificate Validation', desc: 'Expiry, SAN verification, self-signed detection, CA analysis' },
  { id: 'security_assessment', label: 'Website Security Assessment', desc: 'Security headers (CSP/HSTS), password form audits, redirect tracking' },
  { id: 'community_intelligence', label: 'Community Threat Intelligence', desc: 'Deduplicated crowd reports & optional external intelligence feeds' },
  { id: 'risk_scoring', label: 'Explainable Risk Scoring Engine', desc: 'Multi-factor severity aggregation with remediation guidance' },
  { id: 'flight_recorder', label: 'Phishing Flight Recorder', desc: 'Historical snapshot capture & infrastructure drift deltas' },
  { id: 'attack_fingerprint', label: 'Attack Family Fingerprinting', desc: 'Evidence-based campaign & shared infrastructure correlation' },
  { id: 'graph_enrichment', label: 'Investigation Graph Enrichment', desc: 'Topology synthesis and entity-relationship resolution' },
];

export default function ScannerHome({ onScanComplete, initialUrl = '' }) {
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
      const res = await fetch('/api/scans?limit=6');
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
          target_url: formatted,
          requested_modules: selectedModules,
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Scan request failed');
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
    <div style={{ maxWidth: 1000, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 28 }}>
      {/* Hero Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(6, 182, 212, 0.08) 100%)',
        border: '1px solid #23304c',
        borderRadius: 16,
        padding: '36px 32px',
        textAlign: 'center',
      }}>
        <span style={{
          background: 'rgba(99, 102, 241, 0.2)', color: '#818cf8',
          padding: '4px 14px', borderRadius: 20, fontSize: 12, fontWeight: 700,
          letterSpacing: '0.06em', textTransform: 'uppercase',
        }}>
          Multi-Stage Digital Threat Investigation
        </span>
        <h2 style={{ fontSize: 32, fontWeight: 800, marginTop: 12, color: '#f8fafc' }}>
          Analyze Suspicious Domains & Phishing Campaigns
        </h2>
        <p style={{ color: '#94a3b8', fontSize: 15, maxWidth: 650, margin: '10px auto 0 auto', lineHeight: 1.6 }}>
          Perform lexical homograph detection, TLS cryptography validation, credential form analysis,
          Flight Recorder snapshots, and evidence-backed attack family clustering.
        </p>

        {/* Scan Input Form */}
        <form onSubmit={handleScanSubmit} style={{ marginTop: 28, display: 'flex', gap: 12, maxWidth: 750, margin: '28px auto 0 auto' }}>
          <input
            type="text"
            placeholder="Enter URL to investigate (e.g., https://paypa1-update.xyz/login)..."
            value={targetUrl}
            onChange={e => setTargetUrl(e.target.value)}
            disabled={scanning}
            style={{
              flex: 1,
              background: '#0a0d14',
              color: '#f8fafc',
              border: '2px solid #23304c',
              padding: '14px 18px',
              borderRadius: 10,
              fontSize: 15,
              fontFamily: 'JetBrains Mono, monospace',
              outline: 'none',
            }}
          />
          <button
            type="submit"
            disabled={scanning || !targetUrl.trim()}
            style={{
              background: scanning ? '#334155' : 'linear-gradient(135deg, #6366f1, #06b6d4)',
              border: 'none',
              color: '#ffffff',
              padding: '0 28px',
              borderRadius: 10,
              fontSize: 15,
              fontWeight: 700,
              cursor: scanning ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              boxShadow: '0 4px 14px rgba(99, 102, 241, 0.4)',
            }}
          >
            {scanning ? 'Scanning Pipeline...' : 'Initiate Scan →'}
          </button>
        </form>

        {error && (
          <div style={{
            background: 'rgba(244, 63, 94, 0.15)',
            border: '1px solid rgba(244, 63, 94, 0.4)',
            color: '#fda4af',
            padding: '10px 16px',
            borderRadius: 8,
            fontSize: 13,
            marginTop: 16,
            maxWidth: 750,
            margin: '16px auto 0 auto',
          }}>
            ⚠️ {error}
          </div>
        )}
      </div>

      {/* Module Configuration */}
      <div style={{
        background: '#151d30',
        borderRadius: 14,
        border: '1px solid #23304c',
        padding: 24,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
            Investigation Engine Pipeline ({selectedModules.length}/{AVAILABLE_MODULES.length} Active)
          </h3>
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              onClick={() => setSelectedModules(AVAILABLE_MODULES.map(m => m.id))}
              style={{ background: 'transparent', border: 'none', color: '#38bdf8', fontSize: 12, cursor: 'pointer' }}
            >
              Select All
            </button>
            <span style={{ color: '#475569' }}>|</span>
            <button
              onClick={() => setSelectedModules([])}
              style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: 12, cursor: 'pointer' }}
            >
              Clear
            </button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
          {AVAILABLE_MODULES.map(mod => {
            const isChecked = selectedModules.includes(mod.id);
            return (
              <label
                key={mod.id}
                onClick={() => toggleModule(mod.id)}
                style={{
                  background: isChecked ? 'rgba(99, 102, 241, 0.08)' : '#0c101c',
                  border: isChecked ? '1px solid rgba(99, 102, 241, 0.4)' : '1px solid #23304c',
                  borderRadius: 10,
                  padding: 14,
                  display: 'flex',
                  gap: 12,
                  cursor: 'pointer',
                  userSelect: 'none',
                }}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={() => {}}
                  style={{ accentColor: '#6366f1', marginTop: 3 }}
                />
                <div>
                  <h4 style={{ fontSize: 13, fontWeight: 600, color: isChecked ? '#f8fafc' : '#94a3b8' }}>
                    {mod.label}
                  </h4>
                  <p style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{mod.desc}</p>
                </div>
              </label>
            );
          })}
        </div>
      </div>

      {/* Recent Investigations */}
      {recentScans.length > 0 && (
        <div style={{
          background: '#151d30',
          borderRadius: 14,
          border: '1px solid #23304c',
          padding: 24,
        }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc', marginBottom: 14 }}>
            Recent Investigations
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {recentScans.map(s => {
              const score = s.risk_score || 0;
              const isHigh = score >= 50;
              return (
                <div
                  key={s.scan_id}
                  onClick={() => onScanComplete(s)}
                  style={{
                    background: '#0c101c',
                    border: '1px solid #23304c',
                    borderRadius: 10,
                    padding: 14,
                    cursor: 'pointer',
                    transition: 'border-color 0.15s ease',
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = '#38bdf8'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = '#23304c'}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{
                      fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 6,
                      background: isHigh ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                      color: isHigh ? '#fda4af' : '#6ee7b7',
                    }}>
                      Score: {score.toFixed(1)}/100
                    </span>
                    <span style={{ fontSize: 11, color: '#64748b' }}>
                      {new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <h4 style={{
                    fontSize: 13, fontWeight: 600, color: '#f8fafc', marginTop: 8,
                    fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                  }}>
                    {s.hostname || s.target_url}
                  </h4>
                  <p style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>
                    Status: {s.status} • Modules: {s.module_results?.length || 0}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
