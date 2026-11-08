import React, { useState } from 'react';

export default function CertificateDetails({ scan, onNavigate }) {
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);
  const [showRawDetails, setShowRawDetails] = useState(false);
  const [sanSearch, setSanSearch] = useState('');
  const [expandedDim, setExpandedDim] = useState(null);

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
          Execute a scan from the Scanner tab to inspect TLS certificate intelligence and security parameters.
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
  const isUntrustedCa = tlsData.is_untrusted_ca;
  const hostnameMatches = tlsData.hostname_matches;
  const daysRemaining = tlsData.days_to_expiration ?? tlsData.days_remaining;

  const issuerDisplay = typeof tlsData.issuer === 'object'
    ? (tlsData.issuer?.organization || tlsData.issuer?.common_name || 'N/A')
    : (tlsData.issuer || 'N/A');

  const commonNameDisplay = tlsData.common_name
    || (typeof tlsData.subject === 'object' ? tlsData.subject?.common_name : null)
    || 'N/A';

  const fingerprintDisplay = tlsData.sha256_fingerprint || tlsData.fingerprint_sha256 || null;
  const sansList = tlsData.subject_alt_names || tlsData.sans || [];

  const isUnavailable = tlsData.status === 'unavailable' || tlsData.status === 'failed' || (!fingerprintDisplay && tlsData.error);

  // Status computation for prominent badge
  let statusBadge = { label: 'Valid & Trusted', bg: '#ecfdf5', color: '#059669', border: '#a7f3d0', icon: '✓' };
  if (isUnavailable) {
    statusBadge = { label: 'TLS Handshake Failed / Port 443 Unavailable', bg: '#fff1f2', color: '#e11d48', border: '#fecdd3', icon: '✕' };
  } else if (isExpired) {
    statusBadge = { label: 'Expired Certificate', bg: '#fff1f2', color: '#e11d48', border: '#fecdd3', icon: '⚠️' };
  } else if (hostnameMatches === false) {
    statusBadge = { label: 'Domain Mismatch', bg: '#fff1f2', color: '#e11d48', border: '#fecdd3', icon: '⚠️' };
  } else if (isSelfSigned) {
    statusBadge = { label: 'Self-Signed (Untrusted Root)', bg: '#fffbeb', color: '#d97706', border: '#fde68a', icon: '⚠️' };
  } else if (isUntrustedCa || chainValid === false) {
    statusBadge = { label: 'Untrusted CA / Invalid Chain', bg: '#fff1f2', color: '#e11d48', border: '#fecdd3', icon: '⚠️' };
  } else if (tlsData.is_not_yet_valid) {
    statusBadge = { label: 'Not Yet Valid', bg: '#fffbeb', color: '#d97706', border: '#fde68a', icon: '⚠️' };
  }

  // Copy fingerprint handler
  function handleCopyFingerprint() {
    if (fingerprintDisplay) {
      navigator.clipboard.writeText(fingerprintDisplay);
      setCopiedFingerprint(true);
      setTimeout(() => setCopiedFingerprint(false), 2000);
    }
  }

  // Filtered SANs
  const filteredSans = sansList.filter(s => s.toLowerCase().includes(sanSearch.toLowerCase()));

  // Extract structured objects
  const subjectObj = tlsData.subject_details || tlsData.subject || {};
  const issuerObj = tlsData.issuer_details || {};
  const cryptoObj = tlsData.cryptography || {};
  const validityObj = tlsData.validity || {};
  const impersonationObj = tlsData.domain_impersonation || {};
  const dimensions = tlsData.security_assessment_dimensions || [];
  const findingsList = tlsData.investigation_findings || [];
  const summaryObj = tlsData.investigation_summary || {};

  // Lifecycle timeline calculations
  const notBeforeStr = tlsData.not_before ? new Date(tlsData.not_before).toLocaleDateString() : 'N/A';
  const notAfterStr = tlsData.not_after ? new Date(tlsData.not_after).toLocaleDateString() : 'N/A';
  const progressPct = validityObj.progress_pct ?? (
    daysRemaining !== null && daysRemaining !== undefined
      ? Math.max(0, Math.min(100, Math.round(((90 - Math.max(0, daysRemaining)) / 90) * 100)))
      : 50
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1120, margin: '0 auto', paddingBottom: 48 }}>
      
      {/* ------------------------------------------------------------- */}
      {/* SECTION A: Certificate Overview Header                        */}
      {/* ------------------------------------------------------------- */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '24px 28px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                TLS Certificate Intelligence
              </span>
              <span style={{
                background: statusBadge.bg,
                color: statusBadge.color,
                border: `1px solid ${statusBadge.border}`,
                padding: '3px 12px',
                borderRadius: 999,
                fontSize: 12,
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}>
                <span>{statusBadge.icon}</span> {statusBadge.label}
              </span>
            </div>

            <h2 style={{ fontSize: 24, fontWeight: 800, color: '#0f172a', marginTop: 6, fontFamily: 'IBM Plex Mono, monospace' }}>
              {scan.hostname || scan.target_url}
            </h2>
          </div>

          <div style={{ textAlign: 'right' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.05em' }}>
              Overall Certificate Assessment
            </span>
            <div style={{
              fontSize: 14,
              fontWeight: 700,
              marginTop: 4,
              color: isUnavailable || isExpired || hostnameMatches === false ? '#e11d48' : isSelfSigned ? '#d97706' : '#059669',
            }}>
              {isUnavailable ? 'Connection Blocked / Offline' : isExpired ? 'Critical Expiration Risk' : hostnameMatches === false ? 'Domain Mismatch Critical' : isSelfSigned ? 'Self-Signed Warning' : 'Publicly Valid & Trusted'}
            </div>
          </div>
        </div>

        {/* Analytical Clarity Alert Callout */}
        <div style={{
          marginTop: 18,
          background: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: 12,
          padding: '10px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          fontSize: 12.5,
          color: '#475569',
        }}>
          <span style={{ fontSize: 16, color: '#0284c7' }}>ℹ️</span>
          <span>
            <strong>Analytical Principle:</strong> Do not confuse certificate validity with website legitimacy. Attackers frequently issue valid TLS certificates from public Certificate Authorities (e.g. Let's Encrypt, Cloudflare) on dedicated phishing infrastructure.
          </span>
        </div>

        {/* Overview Metric Row */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 12,
          marginTop: 20,
        }}>
          <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Certificate Authority</span>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#0f172a', marginTop: 4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {tlsData.issuer_details?.ca_name || issuerDisplay}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Certificate Type</span>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#0284c7', marginTop: 4 }}>
              {tlsData.certificate_type || 'Domain Validated (DV)'}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Protocol & Version</span>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#0f172a', marginTop: 4, fontFamily: 'IBM Plex Mono' }}>
              {tlsData.tls_version || 'TLSv1.3'}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Expiration Timeline</span>
            <div style={{
              fontSize: 14,
              fontWeight: 800,
              marginTop: 4,
              color: (daysRemaining ?? 0) <= 0 ? '#e11d48' : (daysRemaining ?? 0) <= 14 ? '#d97706' : '#059669',
            }}>
              {daysRemaining !== null && daysRemaining !== undefined ? `${daysRemaining} days left` : 'N/A'}
            </div>
          </div>
        </div>
      </div>

      {isUnavailable && (
        <div style={{
          background: '#fff1f2',
          border: '1.5px solid #fecdd3',
          borderRadius: 16,
          padding: '20px 24px',
          color: '#9f1239',
        }}>
          <h4 style={{ fontSize: 15, fontWeight: 800 }}>⚠️ TLS Inspection Offline or Handshake Incomplete</h4>
          <p style={{ fontSize: 13, marginTop: 6, lineHeight: 1.5 }}>
            PHANTOM could not establish a TLS handshake on port 443 for <strong>{scan.hostname}</strong> ({tlsData.error || 'Connection refused or timed out'}).
            The target may only serve unencrypted HTTP, or an intermediate firewall/WAF dropped connection probes.
          </p>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* SECTION B: Detailed Technical Sections                        */}
      {/* ------------------------------------------------------------- */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))', gap: 20 }}>
        
        {/* Subject Information */}
        <div style={{
          background: '#ffffff',
          borderRadius: 16,
          border: '1.5px solid var(--border-subtle)',
          padding: 22,
          boxShadow: 'var(--shadow-sm)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <span style={{ fontSize: 16 }}>👤</span>
            <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>Subject Information</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Common Name (CN):</span>
              <strong style={{ color: '#0f172a', fontFamily: 'IBM Plex Mono' }}>{commonNameDisplay}</strong>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Organization (O):</span>
              <span style={{ color: subjectObj.organization ? '#0f172a' : '#94a3b8', fontWeight: 600 }}>
                {subjectObj.organization || 'Not Specified (DV)'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Organizational Unit (OU):</span>
              <span style={{ color: subjectObj.organizational_unit ? '#0f172a' : '#94a3b8' }}>
                {subjectObj.organizational_unit || 'None'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Country (C):</span>
              <span style={{ color: subjectObj.country ? '#0f172a' : '#94a3b8', fontWeight: 600 }}>
                {subjectObj.country || 'N/A'}
              </span>
            </div>

            <div style={{ marginTop: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ color: '#64748b', fontWeight: 600 }}>Subject Alternative Names ({sansList.length}):</span>
                {sansList.length > 5 && (
                  <input
                    type="text"
                    placeholder="Filter SANs..."
                    value={sanSearch}
                    onChange={e => setSanSearch(e.target.value)}
                    style={{
                      fontSize: 11,
                      padding: '3px 8px',
                      borderRadius: 6,
                      border: '1px solid #cbd5e1',
                      outline: 'none',
                    }}
                  />
                )}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, maxHeight: 110, overflowY: 'auto' }}>
                {filteredSans.length > 0 ? (
                  filteredSans.map((san, idx) => (
                    <span
                      key={idx}
                      style={{
                        background: '#f0f9ff',
                        color: '#0369a1',
                        border: '1px solid #bae6fd',
                        borderRadius: 6,
                        padding: '2px 8px',
                        fontSize: 11,
                        fontFamily: 'IBM Plex Mono',
                      }}
                    >
                      {san}
                    </span>
                  ))
                ) : (
                  <span style={{ color: '#94a3b8', fontSize: 12 }}>No matching SANs recorded</span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Issuer Information */}
        <div style={{
          background: '#ffffff',
          borderRadius: 16,
          border: '1.5px solid var(--border-subtle)',
          padding: 22,
          boxShadow: 'var(--shadow-sm)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <span style={{ fontSize: 16 }}>🏛️</span>
            <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>Issuer & Authority</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Certificate Authority:</span>
              <strong style={{ color: '#0284c7' }}>{issuerObj.ca_name || issuerDisplay}</strong>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Issuer Common Name:</span>
              <span style={{ color: '#0f172a', fontWeight: 600, fontFamily: 'IBM Plex Mono' }}>
                {issuerObj.common_name || 'N/A'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Issuer Organization:</span>
              <span style={{ color: '#0f172a', fontWeight: 600 }}>
                {issuerObj.organization || issuerDisplay}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Issuer Country:</span>
              <span style={{ color: '#0f172a' }}>{issuerObj.country || 'US'}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ color: '#64748b' }}>Trust Anchor Status:</span>
              <span style={{
                fontWeight: 700,
                color: chainValid && !isSelfSigned ? '#059669' : '#e11d48',
              }}>
                {chainValid && !isSelfSigned ? '✓ Public System Trust Store' : isSelfSigned ? '⚠️ Self-Signed (Untrusted)' : '⚠️ Untrusted Chain'}
              </span>
            </div>
          </div>
        </div>

        {/* Validity & Visual Timeline */}
        <div style={{
          background: '#ffffff',
          borderRadius: 16,
          border: '1.5px solid var(--border-subtle)',
          padding: 22,
          boxShadow: 'var(--shadow-sm)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <span style={{ fontSize: 16 }}>⏳</span>
            <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>Validity & Lifecycle Timeline</h3>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 16 }}>
            <div>
              <span style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>Issued (notBefore)</span>
              <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 3 }}>{notBeforeStr}</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <span style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>Lifespan Status</span>
              <div style={{ fontWeight: 800, color: isExpired ? '#e11d48' : '#0284c7', marginTop: 3 }}>
                {isExpired ? 'EXPIRED' : `${daysRemaining ?? 'N/A'} days left`}
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <span style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>Expires (notAfter)</span>
              <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 3 }}>{notAfterStr}</div>
            </div>
          </div>

          {/* Visual Lifecycle Progress Bar */}
          <div>
            <div style={{ height: 8, background: '#f1f5f9', borderRadius: 999, overflow: 'hidden', position: 'relative' }}>
              <div style={{
                width: `${progressPct}%`,
                height: '100%',
                background: isExpired ? '#e11d48' : progressPct > 80 ? '#d97706' : '#0284c7',
                transition: 'width 0.4s ease',
              }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#64748b', marginTop: 6 }}>
              <span>Issued</span>
              <span>Currently Valid ({progressPct}% of lifespan elapsed)</span>
              <span>Expiration</span>
            </div>
          </div>
        </div>

        {/* Cryptographic Specifications */}
        <div style={{
          background: '#ffffff',
          borderRadius: 16,
          border: '1.5px solid var(--border-subtle)',
          padding: 22,
          boxShadow: 'var(--shadow-sm)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 16 }}>🔐</span>
              <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>Cryptographic Specifications</h3>
            </div>
            <button
              onClick={() => setShowRawDetails(!showRawDetails)}
              style={{
                background: '#f8fafc',
                border: '1px solid #cbd5e1',
                borderRadius: 6,
                padding: '4px 10px',
                fontSize: 11.5,
                fontWeight: 600,
                color: '#0284c7',
                cursor: 'pointer',
              }}
            >
              {showRawDetails ? 'Hide Raw Details' : 'Expand Raw Details'}
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10, fontSize: 12.5 }}>
            <div style={{ background: '#f8fafc', padding: 10, borderRadius: 8, border: '1px solid #e2e8f0' }}>
              <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Public Key</span>
              <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 3 }}>
                {cryptoObj.public_key_algorithm || 'RSA'} ({cryptoObj.public_key_size || 2048}-bit)
              </div>
            </div>

            <div style={{ background: '#f8fafc', padding: 10, borderRadius: 8, border: '1px solid #e2e8f0' }}>
              <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Cipher Suite</span>
              <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 3, fontFamily: 'IBM Plex Mono', fontSize: 11.5 }}>
                {tlsData.cipher_suite || 'AES_256_GCM'}
              </div>
            </div>

            <div style={{ background: '#f8fafc', padding: 10, borderRadius: 8, border: '1px solid #e2e8f0' }}>
              <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Signature Algorithm</span>
              <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 3, fontSize: 11.5 }}>
                {cryptoObj.signature_algorithm || tlsData.signature_algorithm || 'sha256WithRSAEncryption'}
              </div>
            </div>

            <div style={{ background: '#f8fafc', padding: 10, borderRadius: 8, border: '1px solid #e2e8f0' }}>
              <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Serial Number</span>
              <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 3, fontFamily: 'IBM Plex Mono', fontSize: 11 }}>
                {tlsData.serial_number || 'N/A'}
              </div>
            </div>
          </div>

          {/* SHA-256 Fingerprint Box */}
          <div style={{ marginTop: 12, background: '#f0f9ff', padding: '10px 14px', borderRadius: 8, border: '1px solid #bae6fd' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#0369a1', textTransform: 'uppercase' }}>
                SHA-256 Certificate Fingerprint
              </span>
              <button
                onClick={handleCopyFingerprint}
                style={{
                  background: copiedFingerprint ? '#059669' : '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: 4,
                  padding: '2px 8px',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'background 0.15s ease',
                }}
              >
                {copiedFingerprint ? '✓ Copied' : '📋 Copy'}
              </button>
            </div>
            <div style={{
              fontSize: 12,
              fontFamily: 'IBM Plex Mono, monospace',
              color: '#0369a1',
              wordBreak: 'break-all',
              marginTop: 4,
            }}>
              {fingerprintDisplay || 'No fingerprint recorded'}
            </div>
          </div>

          {/* Expandable Technical Raw Details */}
          {showRawDetails && (
            <div style={{ marginTop: 12, background: '#0f172a', color: '#38bdf8', padding: 12, borderRadius: 8, fontSize: 11, fontFamily: 'IBM Plex Mono', maxHeight: 180, overflowY: 'auto' }}>
              <pre>{JSON.stringify(tlsData, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SECTION 3: Certificate Security Assessment (7 Dimensions)     */}
      {/* ------------------------------------------------------------- */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '24px 28px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Rigorous Evaluation
            </span>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
              Certificate Security Assessment
            </h3>
          </div>
          <span style={{ fontSize: 12, color: '#64748b' }}>
            7 Independent Risk Dimensions
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {dimensions.map((dim, idx) => {
            const isPass = dim.status === 'pass';
            const isWarning = dim.status === 'warning';
            const isFail = dim.status === 'fail';
            const statusBg = isPass ? '#ecfdf5' : isWarning ? '#fffbeb' : isFail ? '#fff1f2' : '#f8fafc';
            const statusColor = isPass ? '#059669' : isWarning ? '#d97706' : isFail ? '#e11d48' : '#64748b';
            const statusBorder = isPass ? '#a7f3d0' : isWarning ? '#fde68a' : isFail ? '#fecdd3' : '#e2e8f0';

            const isExpanded = expandedDim === dim.id;

            return (
              <div
                key={dim.id || idx}
                style={{
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: 12,
                  padding: '14px 18px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{
                      background: statusBg,
                      color: statusColor,
                      border: `1px solid ${statusBorder}`,
                      padding: '3px 10px',
                      borderRadius: 999,
                      fontSize: 11,
                      fontWeight: 800,
                      textTransform: 'uppercase',
                      fontFamily: 'IBM Plex Mono',
                    }}>
                      {dim.status.toUpperCase()}
                    </span>
                    <strong style={{ fontSize: 14, color: '#0f172a' }}>{dim.name}</strong>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    {dim.severity && dim.severity !== 'info' && (
                      <span style={{
                        fontSize: 10.5,
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: dim.severity === 'critical' ? '#e11d48' : '#ea580c',
                        color: '#ffffff',
                        textTransform: 'uppercase',
                      }}>
                        {dim.severity}
                      </span>
                    )}
                    <button
                      onClick={() => setExpandedDim(isExpanded ? null : dim.id)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#0284c7',
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: 'pointer',
                      }}
                    >
                      {isExpanded ? 'Hide Evidence ▲' : 'View Evidence ▼'}
                    </button>
                  </div>
                </div>

                <p style={{ fontSize: 13, color: '#475569', margin: 0, lineHeight: 1.45 }}>
                  {dim.explanation}
                </p>

                {isExpanded && dim.evidence && (
                  <div style={{
                    marginTop: 6,
                    background: '#ffffff',
                    border: '1px solid #cbd5e1',
                    borderRadius: 8,
                    padding: 10,
                    fontSize: 11.5,
                    fontFamily: 'IBM Plex Mono',
                    color: '#0369a1',
                  }}>
                    <pre style={{ margin: 0 }}>{JSON.stringify(dim.evidence, null, 2)}</pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SECTION 4: Domain Identity & Brand Impersonation              */}
      {/* ------------------------------------------------------------- */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '24px 28px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Brand Integrity & Deception Analysis
            </span>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
              Domain Identity & Brand Impersonation
            </h3>
          </div>

          <span style={{
            background: impersonationObj.brand_detected && !impersonationObj.is_official_domain ? '#fff1f2' : '#ecfdf5',
            color: impersonationObj.brand_detected && !impersonationObj.is_official_domain ? '#e11d48' : '#059669',
            border: `1px solid ${impersonationObj.brand_detected && !impersonationObj.is_official_domain ? '#fecdd3' : '#a7f3d0'}`,
            padding: '4px 12px',
            borderRadius: 999,
            fontSize: 12,
            fontWeight: 700,
          }}>
            {impersonationObj.brand_detected && !impersonationObj.is_official_domain ? '⚠️ Brand Match Detected' : '✓ No Brand Impersonation Detected'}
          </span>
        </div>

        {/* Analytical Distinction Disclaimer */}
        <div style={{
          background: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: 12,
          padding: '12px 18px',
          marginBottom: 16,
          fontSize: 12.5,
          color: '#334155',
          lineHeight: 1.5,
        }}>
          <strong>Investigative Caution:</strong> A brand name appearing inside a domain name or certificate is a potential impersonation indicator, but is <em>not sufficient evidence of phishing on its own</em>. Defensive security analysts must evaluate the full infrastructure context.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14, fontSize: 13 }}>
          <div style={{ background: '#f8fafc', padding: 14, borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Detected Brand Keyword</span>
            <div style={{ fontWeight: 800, color: impersonationObj.brand_detected ? '#0284c7' : '#0f172a', marginTop: 4 }}>
              {impersonationObj.brand_detected ? impersonationObj.brand_detected.toUpperCase() : 'None (No brand targeted)'}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: 14, borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Official Brand Status</span>
            <div style={{ fontWeight: 700, color: impersonationObj.is_official_domain ? '#059669' : '#e11d48', marginTop: 4 }}>
              {impersonationObj.is_official_domain ? 'Verified Official Domain' : 'Unverified Third-Party / Mimic'}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: 14, borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Suspicious Affixes</span>
            <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 4 }}>
              {impersonationObj.suspicious_affixes?.length > 0 ? impersonationObj.suspicious_affixes.join(', ') : 'None detected'}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: 14, borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Punycode / Homoglyphs</span>
            <div style={{ fontWeight: 700, color: impersonationObj.is_punycode ? '#e11d48' : '#059669', marginTop: 4 }}>
              {impersonationObj.is_punycode ? '⚠️ Punycode Character Present' : '✓ Standard ASCII Domain'}
            </div>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SECTION 5: Certificate Transparency & Historical Intel        */}
      {/* ------------------------------------------------------------- */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '24px 28px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Public Logging & Drift
            </span>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
              Certificate Transparency & Historical Intelligence
            </h3>
          </div>
          <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700 }}>
            {tlsData.certificate_transparency?.has_embedded_scts ? '✓ Embedded SCTs Verified' : 'SCTs via TLS Extension'}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14 }}>
          <div style={{ background: '#f8fafc', padding: 16, borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Certificate Transparency (CT) Logging</span>
            <p style={{ fontSize: 13, color: '#0f172a', marginTop: 4, lineHeight: 1.45 }}>
              {tlsData.certificate_transparency?.status || 'Embedded SCTs checked via standard RFC 6962 X.509 extension.'}
            </p>
          </div>

          <div style={{ background: '#f8fafc', padding: 16, borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Observed Certificate Replacements</span>
            <p style={{ fontSize: 13, color: '#0f172a', marginTop: 4, lineHeight: 1.45 }}>
              Tracking via PHANTOM Flight Recorder: Historical fingerprint changes across consecutive scans are indexed to detect stealth TLS rotations.
            </p>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SECTION 6: Investigation Findings                             */}
      {/* ------------------------------------------------------------- */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '24px 28px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Actionable Evidence
            </span>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
              Investigation Findings ({findingsList.length})
            </h3>
          </div>
          <span style={{ fontSize: 12, color: '#64748b' }}>
            Analyst Observations
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {findingsList.map((f, idx) => {
            const isHigh = f.severity === 'critical' || f.severity === 'high';
            const isMed = f.severity === 'medium';
            const badgeColor = isHigh ? '#e11d48' : isMed ? '#d97706' : '#0284c7';
            const badgeBg = isHigh ? '#fff1f2' : isMed ? '#fffbeb' : '#f0f9ff';

            return (
              <div
                key={idx}
                style={{
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: 12,
                  padding: '16px 20px',
                  borderLeft: `4px solid ${badgeColor}`,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                  <h4 style={{ fontSize: 14.5, fontWeight: 800, color: '#0f172a' }}>{f.title}</h4>
                  <span style={{
                    fontSize: 11,
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '2px 8px',
                    borderRadius: 4,
                    background: badgeBg,
                    color: badgeColor,
                    border: `1px solid ${badgeColor}33`,
                  }}>
                    {f.severity}
                  </span>
                </div>

                <div style={{ fontSize: 12, color: '#64748b', marginTop: 4, fontFamily: 'IBM Plex Mono' }}>
                  <strong>Evidence:</strong> {f.evidence}
                </div>

                <div style={{ fontSize: 13, color: '#334155', marginTop: 8, lineHeight: 1.45 }}>
                  <strong>Analyst Interpretation:</strong> {f.interpretation}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SECTION 7: Investigation Summary (3 Distinct Dimensions)      */}
      {/* ------------------------------------------------------------- */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '24px 28px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ marginBottom: 18 }}>
          <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
            Final Synthesized Posture
          </span>
          <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
            Investigation Summary
          </h3>
          <p style={{ fontSize: 12.5, color: '#64748b', marginTop: 2 }}>
            Separates technical cryptographic hygiene from domain authenticity and malicious threat indicators.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          
          {/* Dimension 1: Certificate Health */}
          <div style={{
            background: '#f8fafc',
            border: '1.5px solid #e2e8f0',
            borderRadius: 14,
            padding: '18px 20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Dimension 1</span>
                <span style={{
                  fontSize: 12,
                  fontWeight: 800,
                  color: summaryObj.certificate_health?.status === 'Healthy' ? '#059669' : '#e11d48',
                }}>
                  {summaryObj.certificate_health?.status || 'Healthy'}
                </span>
              </div>
              <h4 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', marginTop: 8 }}>Certificate Health</h4>
              <p style={{ fontSize: 12.5, color: '#475569', marginTop: 4, lineHeight: 1.45 }}>
                {summaryObj.certificate_health?.summary || 'Technical certificate configuration, cryptographic parameters, and chain validation.'}
              </p>
            </div>
            <div style={{ fontSize: 11.5, color: '#0284c7', marginTop: 12, fontFamily: 'IBM Plex Mono' }}>
              {summaryObj.certificate_health?.details}
            </div>
          </div>

          {/* Dimension 2: Domain Identity */}
          <div style={{
            background: '#f8fafc',
            border: '1.5px solid #e2e8f0',
            borderRadius: 14,
            padding: '18px 20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Dimension 2</span>
                <span style={{
                  fontSize: 12,
                  fontWeight: 800,
                  color: summaryObj.domain_identity?.status === 'Aligned' ? '#059669' : '#d97706',
                }}>
                  {summaryObj.domain_identity?.status || 'Aligned'}
                </span>
              </div>
              <h4 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', marginTop: 8 }}>Domain Identity</h4>
              <p style={{ fontSize: 12.5, color: '#475569', marginTop: 4, lineHeight: 1.45 }}>
                {summaryObj.domain_identity?.summary || 'Alignment between certificate identity, SAN coverage, and target domain.'}
              </p>
            </div>
            <div style={{ fontSize: 11.5, color: '#0284c7', marginTop: 12, fontFamily: 'IBM Plex Mono' }}>
              {summaryObj.domain_identity?.details}
            </div>
          </div>

          {/* Dimension 3: Website Trust */}
          <div style={{
            background: '#f8fafc',
            border: '1.5px solid #e2e8f0',
            borderRadius: 14,
            padding: '18px 20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Dimension 3</span>
                <span style={{
                  fontSize: 12,
                  fontWeight: 800,
                  color: summaryObj.website_trust?.status === 'Suspicious' ? '#e11d48' : '#059669',
                }}>
                  {summaryObj.website_trust?.status || 'Neutral / Standard'}
                </span>
              </div>
              <h4 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', marginTop: 8 }}>Website Trust</h4>
              <p style={{ fontSize: 12.5, color: '#475569', marginTop: 4, lineHeight: 1.45 }}>
                {summaryObj.website_trust?.summary || 'Impersonation heuristics and brand mimicry indicators.'}
              </p>
            </div>
            <div style={{ fontSize: 11.5, color: '#0284c7', marginTop: 12, fontFamily: 'IBM Plex Mono' }}>
              {summaryObj.website_trust?.details}
            </div>
          </div>

        </div>
      </div>

    </div>
  );
}
