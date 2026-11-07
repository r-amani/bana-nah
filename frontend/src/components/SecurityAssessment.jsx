import React from 'react';

export default function SecurityAssessment({ scan, onNavigate }) {
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
            <path d="M12 3 5 6v5.5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6z"></path>
            <path d="m9 12 2.2 2.2L15.5 10"></path>
          </svg>
        </div>
        <h3 style={{ fontSize: 20, fontWeight: 800, color: '#0f172a' }}>No Target Analyzed</h3>
        <p style={{ color: '#64748b', marginTop: 8, fontSize: 14 }}>
          Execute a scan from the Scanner tab to review DOM & security headers assessment.
        </p>
        {onNavigate && (
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
        )}
      </div>
    );
  }

  const secMod = scan.module_results?.find(m => m.module === 'security_assessment');
  const secData = secMod?.data || {};

  const headers = secData.security_headers || {};
  const dom = secData.dom_analysis || {};
  const redirects = secData.redirects || {};

  const HEADERS_LIST = [
    { key: 'hsts', name: 'Strict-Transport-Security (HSTS)', desc: 'Enforces HTTPS encryption on clients' },
    { key: 'csp', name: 'Content-Security-Policy (CSP)', desc: 'Prevents XSS, script injection, and frame theft' },
    { key: 'x_frame_options', name: 'X-Frame-Options', desc: 'Defends against Clickjacking UI redress attacks' },
    { key: 'x_content_type_options', name: 'X-Content-Type-Options', desc: 'Blocks MIME-type sniffing exploits' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1050, margin: '0 auto' }}>
      {/* Security Headers Matrix */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
          Defenses Audit
        </span>
        <h3 style={{ fontSize: 22, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
          Security Headers Audit Matrix
        </h3>
        <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
          Verification of browser defense-in-depth headers protecting against clickjacking, sniffing, and protocol downgrade.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14, marginTop: 20 }}>
          {HEADERS_LIST.map(h => {
            const isPresent = Boolean(headers[h.key]);
            return (
              <div
                key={h.key}
                style={{
                  background: isPresent ? '#f0fdf4' : '#fff1f2',
                  border: isPresent ? '1.5px solid #bbf7d0' : '1.5px solid #fecdd3',
                  borderRadius: 14,
                  padding: 16,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <h4 style={{ fontSize: 13.5, fontWeight: 700, color: '#0f172a' }}>{h.name}</h4>
                  <p style={{ fontSize: 11.5, color: '#64748b', marginTop: 3 }}>{h.desc}</p>
                </div>
                <span style={{
                  padding: '4px 10px',
                  borderRadius: 999,
                  fontSize: 11,
                  fontWeight: 800,
                  background: isPresent ? '#dcfce7' : '#fee2e2',
                  color: isPresent ? '#15803d' : '#b91c1c',
                  whiteSpace: 'nowrap',
                }}>
                  {isPresent ? '✓ ENFORCED' : '✗ MISSING'}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* DOM & Form Heuristics */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
          DOM Inspection
        </span>
        <h3 style={{ fontSize: 22, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
          Structure & Credential Form Analysis
        </h3>
        <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
          Passive inspection of HTML inputs, external submission targets, and hidden elements.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14, marginTop: 20 }}>
          <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Password Inputs
            </span>
            <div style={{ fontSize: 26, fontWeight: 800, color: '#0f172a', marginTop: 6, fontFamily: 'IBM Plex Mono' }}>
              {dom.password_inputs_count || 0}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Cross-Domain Form Actions
            </span>
            <div style={{
              fontSize: 26,
              fontWeight: 800,
              fontFamily: 'IBM Plex Mono',
              marginTop: 6,
              color: dom.cross_domain_forms?.length > 0 ? '#e11d48' : '#059669',
            }}>
              {dom.cross_domain_forms?.length || 0}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Hidden Iframes
            </span>
            <div style={{
              fontSize: 26,
              fontWeight: 800,
              fontFamily: 'IBM Plex Mono',
              marginTop: 6,
              color: dom.hidden_iframes_count > 0 ? '#d97706' : '#059669',
            }}>
              {dom.hidden_iframes_count || 0}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Meta Refresh Tag
            </span>
            <div style={{
              fontSize: 24,
              fontWeight: 800,
              fontFamily: 'IBM Plex Mono',
              marginTop: 6,
              color: dom.has_meta_refresh ? '#e11d48' : '#059669',
            }}>
              {dom.has_meta_refresh ? 'DETECTED' : 'NONE'}
            </div>
          </div>
        </div>
      </div>

      {/* Redirect Chain */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
          Routing & Hops
        </span>
        <h3 style={{ fontSize: 22, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
          Redirect Chain & Routing Trajectory
        </h3>
        <div style={{ marginTop: 14, fontSize: 14, color: '#334155' }}>
          <div><strong>Total Redirect Hops:</strong> <span style={{ fontFamily: 'IBM Plex Mono', color: '#0f172a', fontWeight: 700 }}>{redirects.hop_count || 0}</span></div>
          <div style={{ marginTop: 8 }}>
            <strong>Final Destination:</strong>{' '}
            <span style={{ fontFamily: 'IBM Plex Mono', color: '#0284c7', fontWeight: 600 }}>
              {redirects.final_url || scan.target_url}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
