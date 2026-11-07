import React from 'react';

export const PAGES = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="9" rx="1.5"></rect>
        <rect x="14" y="3" width="7" height="5" rx="1.5"></rect>
        <rect x="14" y="12" width="7" height="9" rx="1.5"></rect>
        <rect x="3" y="16" width="7" height="5" rx="1.5"></rect>
      </svg>
    ),
  },
  {
    id: 'scanner',
    label: 'Scanner',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="6.5"></circle>
        <path d="m20 20-4.2-4.2"></path>
      </svg>
    ),
  },
  { type: 'divider', id: 'div1' },
  {
    id: 'report',
    label: 'Scan Report',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"></path>
        <path d="M14 3v5h5"></path>
        <path d="M9 13h6M9 17h6"></path>
      </svg>
    ),
  },
  {
    id: 'certificate',
    label: 'TLS Certificate',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="4.5" y="10.5" width="15" height="10" rx="2.5"></rect>
        <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"></path>
      </svg>
    ),
  },
  {
    id: 'assessment',
    label: 'Security Assessment',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 3 5 6v5.5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6z"></path>
        <path d="m9 12 2.2 2.2L15.5 10"></path>
      </svg>
    ),
  },
  { type: 'divider', id: 'div2' },
  {
    id: 'flight_recorder',
    label: 'Flight Recorder',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1L3.5 8.5"></path>
        <path d="M3.5 4v4.5H8"></path>
        <path d="M12 8v4.2l2.8 1.8"></path>
      </svg>
    ),
  },
  {
    id: 'community',
    label: 'Community Reports',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="9" cy="8.5" r="3.2"></circle>
        <path d="M3.5 19a5.5 5.5 0 0 1 11 0"></path>
        <path d="M16 5.6a3.2 3.2 0 0 1 0 5.8M18 14.2a5.5 5.5 0 0 1 2.5 4.8"></path>
      </svg>
    ),
  },
  {
    id: 'graph',
    label: 'Investigation Graph',
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

export default function Navigation({ activePage, setActivePage }) {
  return (
    <nav className="rail-nav" aria-label="Primary Navigation">
      {/* Brand Icon Shield */}
      <div
        onClick={() => setActivePage('scanner')}
        title="PHANTOM Threat Platform"
        style={{
          width: 48,
          height: 48,
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #0284c7, #38bdf8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          cursor: 'pointer',
          marginBottom: 14,
          boxShadow: '0 4px 10px rgba(2, 132, 199, 0.35)',
          color: '#ffffff',
          flexShrink: 0,
        }}
      >
        <svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 3 5 6v5.5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6z"></path>
          <path d="m9 12 2.2 2.2L15.5 10"></path>
        </svg>
      </div>

      {/* Nav Items */}
      {PAGES.map(item => {
        if (item.type === 'divider') {
          return <div key={item.id} className="rail-divider" aria-hidden="true" />;
        }

        const isActive = activePage === item.id;
        return (
          <button
            key={item.id}
            type="button"
            className={`rail-btn ${isActive ? 'active' : ''}`}
            onClick={() => setActivePage(item.id)}
            aria-label={item.label}
            title={item.label}
            aria-current={isActive ? 'page' : undefined}
          >
            {item.icon}
          </button>
        );
      })}
    </nav>
  );
}
