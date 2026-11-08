import React, { useState, useEffect } from 'react';
import Navigation from './components/Navigation.jsx';
import Dashboard from './components/Dashboard.jsx';
import ScannerHome from './components/ScannerHome.jsx';
import ScanReport from './components/ScanReport.jsx';
import CertificateDetails from './components/CertificateDetails.jsx';
import SecurityAssessment from './components/SecurityAssessment.jsx';
import FlightRecorder from './components/FlightRecorder.jsx';
import CommunityReports from './components/CommunityReports.jsx';
import InvestigationGraph from './components/InvestigationGraph.jsx';

export default function App() {
  const [activePage, setActivePage] = useState('scanner');
  const [currentScan, setCurrentScan] = useState(null);
  const [targetDomain, setTargetDomain] = useState('');

  // Auto-hydrate latest scan if available so detail views are not empty on reload
  useEffect(() => {
    async function loadLatestScan() {
      try {
        const res = await fetch('/api/scans?limit=1');
        if (res.ok) {
          const list = await res.json();
          if (list && list.length > 0 && !currentScan) {
            setCurrentScan(list[0]);
            setTargetDomain(list[0].hostname || '');
          }
        }
      } catch (err) {
        // Degrades silently
      }
    }
    loadLatestScan();
  }, []);

  function handleScanComplete(scan) {
    setCurrentScan(scan);
    setTargetDomain(scan.hostname || '');
    setActivePage('report');
  }

  function handleSelectDomainForScan(domain) {
    setTargetDomain(domain);
    setActivePage('scanner');
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', background: 'var(--bg-app)' }}>
      {/* Left Vertical Rail */}
      <Navigation
        activePage={activePage}
        setActivePage={setActivePage}
        currentScan={currentScan}
      />

      {/* Main Content Area */}
      <div style={{ flex: '1 1 auto', display: 'flex', flexDirection: 'column', minWidth: 0, minHeight: '100vh' }}>
        {/* Top Header */}
        <header style={{
          height: 64,
          padding: '0 32px',
          background: '#ffffff',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          position: 'sticky',
          top: 0,
          zIndex: 40,
          boxShadow: '0 1px 3px rgba(15, 23, 42, 0.03)',
        }}>
          {/* Brand & Subtitle */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div
              onClick={() => setActivePage('scanner')}
              style={{
                fontSize: 18,
                fontWeight: 800,
                letterSpacing: '.08em',
                color: '#0f172a',
                cursor: 'pointer',
              }}
            >
              PHANTOM
            </div>
            <div style={{ width: 1, height: 16, background: '#cbd5e1' }} />
            <div style={{ fontSize: 13, color: '#64748b', fontWeight: 500 }}>
              Threat Investigation Platform
            </div>
          </div>

          {/* Right Status Badge */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {currentScan ? (
              <div
                onClick={() => setActivePage('report')}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 10,
                  height: 38,
                  padding: '0 14px',
                  borderRadius: 999,
                  border: '1.5px solid var(--border-subtle)',
                  background: '#f8fafc',
                  fontSize: 13,
                  fontWeight: 500,
                  color: '#1e293b',
                  cursor: 'pointer',
                  boxShadow: 'var(--shadow-sm)',
                  transition: 'all 0.15s ease',
                }}
              >
                <span
                  style={{
                    width: 9,
                    height: 9,
                    borderRadius: '50%',
                    background: (currentScan.risk_score || 0) >= 50 ? '#e11d48' : '#059669',
                    boxShadow: (currentScan.risk_score || 0) >= 50
                      ? '0 0 0 3px rgba(225, 29, 72, 0.2)'
                      : '0 0 0 3px rgba(5, 150, 105, 0.2)',
                  }}
                />
                <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, fontWeight: 600 }}>
                  {currentScan.hostname || currentScan.target_url}
                </span>
                <span style={{
                  fontSize: 11,
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: 999,
                  background: (currentScan.risk_score || 0) >= 50 ? '#fff1f2' : '#ecfdf5',
                  color: (currentScan.risk_score || 0) >= 50 ? '#e11d48' : '#059669',
                }}>
                  {(currentScan.risk_score || 0).toFixed(0)}/100
                </span>
              </div>
            ) : (
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 9,
                height: 36,
                padding: '0 16px',
                borderRadius: 999,
                border: '1px solid #bfdbfe',
                background: '#f0f9ff',
                fontSize: 13,
                fontWeight: 600,
                color: '#0284c7',
              }}>
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: '#0284c7',
                    boxShadow: '0 0 0 3px rgba(2, 132, 199, 0.2)',
                  }}
                />
                Ready for investigation
              </div>
            )}
          </div>
        </header>

        {/* Page Content Body */}
        <main style={{ flex: '1 1 auto', padding: '28px 36px 40px', overflowY: 'auto' }}>
          {activePage === 'dashboard' && (
            <Dashboard
              onNavigate={setActivePage}
              onSelectScan={(scan) => { setCurrentScan(scan); setTargetDomain(scan.hostname || ''); }}
            />
          )}

          {activePage === 'scanner' && (
            <ScannerHome
              onScanComplete={handleScanComplete}
              initialUrl={targetDomain ? `https://${targetDomain}` : ''}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'report' && (
            <ScanReport
              scan={currentScan}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'certificate' && (
            <CertificateDetails
              scan={currentScan}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'assessment' && (
            <SecurityAssessment
              scan={currentScan}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'flight_recorder' && (
            <FlightRecorder
              hostname={targetDomain}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'community' && (
            <CommunityReports
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'graph' && (
            <InvestigationGraph
              scanId={currentScan?.scan_id}
              targetDomain={targetDomain}
              onSelectDomain={handleSelectDomainForScan}
            />
          )}
        </main>
      </div>
    </div>
  );
}
