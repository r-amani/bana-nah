import React from 'react';

export default function CertificateDetails({ scan, onNavigate }) {
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
            <rect x="4.5" y="10.5" width="15" height="10" rx="2.5"></rect>
            <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"></path>
          </svg>
        </div>
        <h3 style={{ fontSize: 20, fontWeight: 800, color: '#0f172a' }}>No Target Analyzed</h3>
        <p style={{ color: '#64748b', marginTop: 8, fontSize: 14 }}>
          Execute a scan from the Scanner tab to inspect TLS certificate parameters.
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

  const tlsMod = scan.module_results?.find(m => m.module === 'tls_validation');
  const tlsData = tlsMod?.data || {};

  const isExpired = tlsData.is_expired;
  const isSelfSigned = tlsData.is_self_signed;
  const chainValid = tlsData.chain_valid;
  const hostnameMatches = tlsData.hostname_matches;
  const daysRemaining = tlsData.days_to_expiration ?? tlsData.days_remaining;

  // Safe accessor fallbacks
  const issuerDisplay = typeof tlsData.issuer === 'object'
    ? (tlsData.issuer?.organization || tlsData.issuer?.common_name || 'N/A')
    : (tlsData.issuer || 'N/A');

  const commonNameDisplay = tlsData.common_name
    || (typeof tlsData.subject === 'object' ? tlsData.subject?.common_name : null)
    || 'N/A';

  const fingerprintDisplay = tlsData.sha256_fingerprint || tlsData.fingerprint_sha256 || null;
  const sansList = tlsData.subject_alt_names || tlsData.sans || [];

  const isUnavailable = tlsData.status === 'unavailable' || tlsData.status === 'failed' || (!fingerprintDisplay && tlsData.error);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1050, margin: '0 auto' }}>
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 14 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Cryptography & Trust
            </span>
            <h2 style={{ fontSize: 24, fontWeight: 800, color: '#0f172a', marginTop: 4, fontFamily: 'IBM Plex Mono, monospace' }}>
              TLS Certificate: {scan.hostname}
            </h2>
          </div>

          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {isUnavailable ? (
              <span style={{
                background: '#fff1f2',
                color: '#e11d48',
                border: '1px solid #fecdd3',
                padding: '5px 14px',
                borderRadius: 999,
                fontSize: 12,
                fontWeight: 700,
              }}>
                ⚠️ TLS Connection Failed / Unavailable
              </span>
            ) : (
              <>
                {isSelfSigned ? (
                  <span style={{
                    background: '#fff1f2',
                    color: '#e11d48',
                    border: '1px solid #fecdd3',
                    padding: '5px 14px',
                    borderRadius: 999,
                    fontSize: 12,
                    fontWeight: 700,
                  }}>
                    ⚠️ Self-Signed Certificate
                  </span>
                ) : chainValid === false ? (
                  <span style={{
                    background: '#fff1f2',
                    color: '#e11d48',
                    border: '1px solid #fecdd3',
                    padding: '5px 14px',
                    borderRadius: 999,
                    fontSize: 12,
                    fontWeight: 700,
                  }}>
                    ⚠️ Untrusted CA / Invalid Chain
                  </span>
                ) : (
                  <span style={{
                    background: '#ecfdf5',
                    color: '#059669',
                    border: '1px solid #a7f3d0',
                    padding: '5px 14px',
                    borderRadius: 999,
                    fontSize: 12,
                    fontWeight: 700,
                  }}>
                    ✓ Publicly Trusted CA
                  </span>
                )}

                {hostnameMatches === false && (
                  <span style={{
                    background: '#fff1f2',
                    color: '#e11d48',
                    border: '1px solid #fecdd3',
                    padding: '5px 14px',
                    borderRadius: 999,
                    fontSize: 12,
                    fontWeight: 700,
                  }}>
                    ⚠️ Hostname Mismatch
                  </span>
                )}

                {isExpired && (
                  <span style={{
                    background: '#fff1f2',
                    color: '#e11d48',
                    border: '1px solid #fecdd3',
                    padding: '5px 14px',
                    borderRadius: 999,
                    fontSize: 12,
                    fontWeight: 700,
                  }}>
                    ⚠️ Expired
                  </span>
                )}

                {!isExpired && daysRemaining !== undefined && daysRemaining <= 14 && daysRemaining >= 0 && (
                  <span style={{
                    background: '#fffbeb',
                    color: '#b45309',
                    border: '1px solid #fde68a',
                    padding: '5px 14px',
                    borderRadius: 999,
                    fontSize: 12,
                    fontWeight: 700,
                  }}>
                    Expiring Soon ({daysRemaining}d)
                  </span>
                )}
              </>
            )}
          </div>
        </div>

        {isUnavailable ? (
          <div style={{
            background: '#fff5f5',
            border: '1.5px solid #fed7d7',
            borderRadius: 14,
            padding: 24,
            marginTop: 24,
            color: '#9b2c2c',
          }}>
            <h4 style={{ margin: 0, fontSize: 16, fontWeight: 800 }}>TLS Handshake Unavailable or Insecure Scheme</h4>
            <p style={{ marginTop: 8, fontSize: 13.5, lineHeight: 1.6, color: '#742a2a' }}>
              PHANTOM could not establish a verified TLS session with <strong>{scan.hostname}</strong>.
              {tlsData.error ? ` Error: ${tlsData.error}.` : ' The target may be serving unencrypted HTTP or port 443 is not accepting secure connections.'}
            </p>
            <div style={{ marginTop: 12, fontSize: 12.5, color: '#9b2c2c' }}>
              <strong>Remediation:</strong> Deploy a valid TLS/HTTPS certificate from an accredited Certificate Authority and enforce HSTS.
            </div>
          </div>
        ) : (
          <>
            {/* Certificate Parameters Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: 16,
              marginTop: 24,
            }}>
              <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
                <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  Subject Common Name (CN)
                </span>
                <div style={{ fontSize: 15, fontWeight: 700, color: '#0f172a', marginTop: 6, fontFamily: 'IBM Plex Mono' }}>
                  {commonNameDisplay}
                </div>
              </div>

              <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
                <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  Issuer Authority
                </span>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#0f172a', marginTop: 6 }}>
                  {issuerDisplay}
                </div>
              </div>

              <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
                <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  Protocol & Cipher Suite
                </span>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#0284c7', marginTop: 6, fontFamily: 'IBM Plex Mono' }}>
                  {tlsData.tls_version || tlsData.tls_protocol || 'TLSv1.3'} • {tlsData.cipher_suite || tlsData.cipher || 'AES_256_GCM'}
                </div>
              </div>

              <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
                <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  Validity Window
                </span>
                <div style={{ fontSize: 12.5, color: '#334155', marginTop: 6, display: 'flex', flexDirection: 'column', gap: 3 }}>
                  <div><strong>Not Before:</strong> {tlsData.not_before || tlsData.valid_from || 'N/A'}</div>
                  <div><strong>Not After:</strong> {tlsData.not_after || tlsData.valid_to || 'N/A'}</div>
                  <div>
                    <strong>Days Remaining:</strong>{' '}
                    <span style={{
                      color: daysRemaining !== undefined && daysRemaining < 15 ? '#e11d48' : '#059669',
                      fontWeight: 700,
                    }}>
                      {daysRemaining !== undefined ? `${daysRemaining} days` : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>

              <div style={{ background: '#f8fafc', padding: 18, borderRadius: 14, border: '1px solid #e2e8f0' }}>
                <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  Root Chain Verification
                </span>
                <div style={{ fontSize: 13, fontWeight: 700, marginTop: 6 }}>
                  {chainValid ? (
                    <span style={{ color: '#059669' }}>✓ Verified by System Root Store</span>
                  ) : (
                    <span style={{ color: '#e11d48' }}>
                      ⚠️ {tlsData.chain_error || 'Untrusted certificate chain'}
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* SHA-256 Fingerprint */}
            <div style={{
              background: '#f8fafc',
              padding: 18,
              borderRadius: 14,
              border: '1px solid #e2e8f0',
              marginTop: 16,
            }}>
              <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                SHA-256 Certificate Fingerprint
              </span>
              <div style={{
                fontSize: 13,
                color: '#0369a1',
                fontFamily: 'IBM Plex Mono',
                wordBreak: 'break-all',
                marginTop: 6,
                fontWeight: 500,
              }}>
                {fingerprintDisplay || 'No fingerprint recorded'}
              </div>
            </div>

            {/* Subject Alternative Names (SANs) */}
            <div style={{
              background: '#f8fafc',
              padding: 18,
              borderRadius: 14,
              border: '1px solid #e2e8f0',
              marginTop: 16,
            }}>
              <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                Subject Alternative Names (SANs) ({sansList.length})
              </span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 10 }}>
                {sansList.length > 0 ? (
                  sansList.map((san, i) => (
                    <span
                      key={i}
                      style={{
                        background: '#f0f9ff',
                        border: '1px solid #bae6fd',
                        color: '#0369a1',
                        padding: '4px 12px',
                        borderRadius: 8,
                        fontSize: 12,
                        fontFamily: 'IBM Plex Mono',
                        fontWeight: 500,
                      }}
                    >
                      {san}
                    </span>
                  ))
                ) : (
                  <span style={{ color: '#94a3b8', fontSize: 13 }}>No SAN entries detected</span>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
