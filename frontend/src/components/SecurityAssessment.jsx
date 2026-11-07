import React from 'react';

export default function SecurityAssessment({ scan }) {
  if (!scan) {
    return (
      <div style={{ textAlign: 'center', padding: 60, background: '#151d30', borderRadius: 14, border: '1px solid #23304c' }}>
        <h3 style={{ fontSize: 18, color: '#f8fafc' }}>No Target Analyzed</h3>
        <p style={{ color: '#94a3b8', marginTop: 8 }}>Execute a scan to review DOM & security headers assessment.</p>
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1000, margin: '0 auto' }}>
      {/* Security Headers Matrix */}
      <div style={{ background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24 }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc' }}>
          Security Headers Audit Matrix
        </h3>
        <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
          Verification of browser defense-in-depth headers protecting against clickjacking, sniffing, and protocol downgrade.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14, marginTop: 20 }}>
          {HEADERS_LIST.map(h => {
            const isPresent = Boolean(headers[h.key]);
            return (
              <div
                key={h.key}
                style={{
                  background: '#0c101c',
                  border: isPresent ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid rgba(244, 63, 94, 0.4)',
                  borderRadius: 10,
                  padding: 16,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc' }}>{h.name}</h4>
                  <p style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>{h.desc}</p>
                </div>
                <span style={{
                  padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 800,
                  background: isPresent ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                  color: isPresent ? '#6ee7b7' : '#fda4af',
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
      <div style={{ background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24 }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc' }}>
          DOM Structure & Credential Form Analysis
        </h3>
        <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
          Passive inspection of HTML inputs, external submission targets, and hidden elements.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14, marginTop: 20 }}>
          <div style={{ background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c' }}>
            <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Password Inputs</span>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#f8fafc', marginTop: 6, fontFamily: 'JetBrains Mono' }}>
              {dom.password_inputs_count || 0}
            </div>
          </div>

          <div style={{ background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c' }}>
            <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Cross-Domain Form Actions</span>
            <div style={{
              fontSize: 24, fontWeight: 800, fontFamily: 'JetBrains Mono', marginTop: 6,
              color: dom.cross_domain_forms?.length > 0 ? '#f43f5e' : '#10b981',
            }}>
              {dom.cross_domain_forms?.length || 0}
            </div>
          </div>

          <div style={{ background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c' }}>
            <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Hidden Iframes</span>
            <div style={{
              fontSize: 24, fontWeight: 800, fontFamily: 'JetBrains Mono', marginTop: 6,
              color: dom.hidden_iframes_count > 0 ? '#f59e0b' : '#10b981',
            }}>
              {dom.hidden_iframes_count || 0}
            </div>
          </div>

          <div style={{ background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c' }}>
            <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Meta Refresh Tag</span>
            <div style={{
              fontSize: 24, fontWeight: 800, fontFamily: 'JetBrains Mono', marginTop: 6,
              color: dom.has_meta_refresh ? '#f43f5e' : '#10b981',
            }}>
              {dom.has_meta_refresh ? 'DETECTED' : 'NONE'}
            </div>
          </div>
        </div>
      </div>

      {/* Redirect Chain */}
      <div style={{ background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24 }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc' }}>
          Redirect Chain & Routing Trajectory
        </h3>
        <div style={{ marginTop: 14, fontSize: 13, color: '#cbd5e1' }}>
          <div><strong>Total Redirect Hops:</strong> {redirects.hop_count || 0}</div>
          <div style={{ marginTop: 6 }}>
            <strong>Final Destination:</strong>{' '}
            <span style={{ fontFamily: 'JetBrains Mono', color: '#38bdf8' }}>
              {redirects.final_url || scan.target_url}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
