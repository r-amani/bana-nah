import React from 'react';

const PAGES = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊' },
  { id: 'scanner', label: 'Scanner', icon: '🔍' },
  { id: 'report', label: 'Scan Report', icon: '📋' },
  { id: 'certificate', label: 'TLS Certificate', icon: '🔒' },
  { id: 'assessment', label: 'Security Assessment', icon: '🛡️' },
  { id: 'flight_recorder', label: 'Flight Recorder', icon: '⏱️' },
  { id: 'community', label: 'Community Reports', icon: '🚩' },
  { id: 'graph', label: 'Investigation Graph', icon: '🌐' },
];

export default function Navigation({ activePage, setActivePage, currentScan }) {
  return (
    <header style={{
      background: '#111726',
      borderBottom: '1px solid #23304c',
      padding: '0 24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      height: 64,
      position: 'sticky',
      top: 0,
      zIndex: 50,
    }}>
      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 10,
          background: 'linear-gradient(135deg, #6366f1, #06b6d4)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 18, color: '#fff', fontWeight: 800,
        }}>
          Ψ
        </div>
        <div>
          <h1 style={{ fontSize: 16, fontWeight: 800, letterSpacing: '0.05em', color: '#f8fafc' }}>
            PHANTOM
          </h1>
          <p style={{ fontSize: 10, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Threat Investigation Platform
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav style={{ display: 'flex', gap: 4, overflowX: 'auto', padding: '0 12px' }}>
        {PAGES.map(page => {
          const isActive = activePage === page.id;
          return (
            <button
              key={page.id}
              onClick={() => setActivePage(page.id)}
              style={{
                background: isActive ? '#1c263d' : 'transparent',
                color: isActive ? '#38bdf8' : '#94a3b8',
                border: 'none',
                borderBottom: isActive ? '2px solid #38bdf8' : '2px solid transparent',
                padding: '12px 14px',
                fontSize: 13,
                fontWeight: isActive ? 600 : 500,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                transition: 'all 0.15s ease',
                whiteSpace: 'nowrap',
              }}
            >
              <span>{page.icon}</span>
              <span>{page.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Target status indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {currentScan ? (
          <div style={{
            background: '#0a0d14',
            border: '1px solid #23304c',
            borderRadius: 8,
            padding: '4px 12px',
            fontSize: 12,
            fontFamily: 'JetBrains Mono, monospace',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: currentScan.risk_score >= 50 ? '#f43f5e' : '#10b981',
            }} />
            <span style={{ color: '#e2e8f0', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {currentScan.hostname || currentScan.target_url}
            </span>
          </div>
        ) : (
          <span style={{ fontSize: 12, color: '#64748b' }}>Ready for Investigation</span>
        )}
      </div>
    </header>
  );
}
