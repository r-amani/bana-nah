import React, { useState } from 'react';
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
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: '#0a0d14' }}>
      <Navigation
        activePage={activePage}
        setActivePage={setActivePage}
        currentScan={currentScan}
      />

      <main style={{ flex: 1, padding: 24 }}>
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
          />
        )}

        {activePage === 'assessment' && (
          <SecurityAssessment
            scan={currentScan}
          />
        )}

        {activePage === 'flight_recorder' && (
          <FlightRecorder
            hostname={targetDomain}
          />
        )}

        {activePage === 'community' && (
          <CommunityReports />
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
  );
}
