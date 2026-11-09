import React, { useState } from 'react';

const Card = ({ children, style = {} }) => (
  <div style={{ background: '#ffffff', borderRadius: 20, border: '1.5px solid var(--border-subtle)', padding: '24px 28px', boxShadow: 'var(--shadow-sm)', ...style }}>
    {children}
  </div>
);

const SubCard = ({ children, style = {} }) => (
  <div style={{ background: '#ffffff', borderRadius: 16, border: '1.5px solid var(--border-subtle)', padding: 22, boxShadow: 'var(--shadow-sm)', ...style }}>
    {children}
  </div>
);

const InfoRow = ({ label, value, mono = false, color, isStrong = false }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 8, borderBottom: '1px solid #f1f5f9' }}>
    <span style={{ color: '#64748b' }}>{label}:</span>
    <span style={{ color: color || '#0f172a', fontWeight: isStrong ? 700 : 600, fontFamily: mono ? 'IBM Plex Mono' : 'inherit' }}>
      {value || 'N/A'}
    </span>
  </div>
);

const MetricBox = ({ label, value, color, mono, style = {} }) => (
  <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: 12, border: '1px solid #e2e8f0', ...style }}>
    <span style={{ fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>{label}</span>
    <div style={{ fontSize: 14, fontWeight: 700, color: color || '#0f172a', marginTop: 4, fontFamily: mono ? 'IBM Plex Mono' : 'inherit' }}>
      {value}
    </div>
  </div>
);

function getPlainEnglishVerdict(scan, tlsData, isUnavailable, daysRemaining) {
  const isExpired = tlsData.is_expired;
  const isSelfSigned = tlsData.is_self_signed;
  const isUntrustedCa = tlsData.is_untrusted_ca || tlsData.chain_valid === false;
  const hostnameMatches = tlsData.hostname_matches;
  const isBrandDetected = tlsData.domain_impersonation?.brand_detected && !tlsData.domain_impersonation?.is_official_domain;
  const brandName = tlsData.domain_impersonation?.brand_detected;

  if (isUnavailable) {
    return {
      headline: 'Target Host Is Offline or Unreachable',
      badgeText: 'Offline / Inactive Host',
      badgeBg: '#f1f5f9', badgeColor: '#475569', badgeBorder: '#cbd5e1',
      borderColor: '#94a3b8', cardBg: '#f8fafc', tagColor: '#64748b',
      explanation: `When PHANTOM attempted to contact ${scan?.hostname || 'this domain'}, the server did not respond on port 443 (HTTPS) or failed DNS lookup (${tlsData.error || 'Connection refused or unresolvable name'}). No live website or digital certificate is currently available to users.`,
      impact: 'You cannot open this website right now. Because the server is offline or unreachable, it cannot actively infect devices or steal credentials in its current state.',
      action: 'No action needed. If you received this link in an email or SMS, ignore it as the link is non-functional or dead.',
      actionColor: '#0369a1',
    };
  }

  if (isBrandDetected) {
    return {
      headline: `High Caution: Suspected ${brandName ? brandName.toUpperCase() : 'Brand'} Lookalike`,
      badgeText: 'Potential Phishing Lure',
      badgeBg: '#fff1f2', badgeColor: '#e11d48', badgeBorder: '#fecdd3',
      borderColor: '#e11d48', cardBg: '#fff5f5', tagColor: '#e11d48',
      explanation: `This domain contains the brand name '${brandName ? brandName.toUpperCase() : 'protected brand'}', but is NOT verified as legitimate infrastructure owned by that company. Attackers frequently register lookalike names to trick visitors into giving up passwords.`,
      impact: 'Interacting with this site puts your account credentials at risk. Fraudulent login forms may capture your username, password, or financial info.',
      action: 'Do NOT enter your password or payment details. If you need to access this service, go directly to the official known website instead.',
      actionColor: '#e11d48',
    };
  }

  if (hostnameMatches === false) {
    return {
      headline: 'Domain Mismatch: Certificate Belongs to a Different Website',
      badgeText: 'Certificate Mismatch',
      badgeBg: '#fff1f2', badgeColor: '#e11d48', badgeBorder: '#fecdd3',
      borderColor: '#e11d48', cardBg: '#fff5f5', tagColor: '#e11d48',
      explanation: `The security certificate presented by this server was issued for a different domain name, not '${scan?.hostname}'. This usually happens when an attacker is intercepting traffic or a server administrator severely misconfigured their domain.`,
      impact: 'Browsers will show a full-screen warning blocking access because it cannot confirm you reached the intended computer.',
      action: 'Do not bypass browser warnings to view this site. The identity of the operator cannot be verified.',
      actionColor: '#e11d48',
    };
  }

  if (isExpired) {
    return {
      headline: 'Security Certificate Has Expired',
      badgeText: 'Expired Certificate',
      badgeBg: '#fff1f2', badgeColor: '#e11d48', badgeBorder: '#fecdd3',
      borderColor: '#e11d48', cardBg: '#fff5f5', tagColor: '#e11d48',
      explanation: `The cryptographic certificate securing this site expired ${Math.abs(daysRemaining || 0)} days ago. Without an active certificate, encrypted traffic is no longer guaranteed safe from eavesdropping or tampering.`,
      impact: 'Modern web browsers will actively prevent you from connecting to prevent outdated encryption vulnerabilities.',
      action: 'Avoid sending sensitive personal or payment information until the site owner renews their security certificate.',
      actionColor: '#ea580c',
    };
  }

  if (isSelfSigned || isUntrustedCa) {
    return {
      headline: 'Untrusted or Self-Made Security Certificate',
      badgeText: 'Untrusted Root Authority',
      badgeBg: '#fffbeb', badgeColor: '#d97706', badgeBorder: '#fde68a',
      borderColor: '#d97706', cardBg: '#fffdf5', tagColor: '#d97706',
      explanation: 'This website is using a self-signed or unauthorized certificate that has not been verified by a publicly trusted Certificate Authority (such as DigiCert, Let\'s Encrypt, or Google Trust Services).',
      impact: 'Anyone on the same network or public Wi-Fi could potentially intercept or alter information sent to this site.',
      action: 'Never enter credit card numbers or passwords on sites with self-signed or untrusted certificates.',
      actionColor: '#d97706',
    };
  }

  return {
    headline: 'Active Website with Valid Encryption (Normal Parameters)',
    badgeText: 'Encrypted & Active',
    badgeBg: '#ecfdf5', badgeColor: '#059669', badgeBorder: '#a7f3d0',
    borderColor: '#059669', cardBg: '#f6fdf9', tagColor: '#059669',
    explanation: `This website possesses a valid, unexpired digital certificate issued by ${tlsData.issuer_details?.ca_name || tlsData.issuer || 'a trusted Certificate Authority'}. All data sent between your browser and this site is securely encrypted in transit.`,
    impact: 'Eavesdroppers on your Wi-Fi cannot see passwords or data submitted to this host. Note: Encryption protects the connection, but does not guarantee the business behind it is trustworthy.',
    action: 'Safe to browse with standard awareness. Always verify who you are dealing with before making purchases or sharing personal documents.',
    actionColor: '#059669',
  };
}

export default function CertificateDetails({ scan, onNavigate }) {
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);
  const [showRawDetails, setShowRawDetails] = useState(false);
  const [sanSearch, setSanSearch] = useState('');
  const [expandedDim, setExpandedDim] = useState(null);

  if (!scan) {
    return (
      <div style={{ textAlign: 'center', padding: '64px 32px', background: '#ffffff', borderRadius: 20, border: '1.5px solid var(--border-subtle)', maxWidth: 700, margin: '40px auto', boxShadow: 'var(--shadow-sm)' }}>
        <div style={{ width: 56, height: 56, borderRadius: '50%', background: '#f0f9ff', color: '#0284c7', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="4.5" y="10.5" width="15" height="10" rx="2.5" /><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
          </svg>
        </div>
        <h3 style={{ fontSize: 20, fontWeight: 800, color: '#0f172a' }}>No Target Analyzed</h3>
        <p style={{ color: '#64748b', marginTop: 8, fontSize: 14 }}>
          Execute a scan from the Scanner tab to inspect TLS certificate intelligence and security parameters.
        </p>
        {onNavigate && (
          <button onClick={() => onNavigate('scanner')} style={{ marginTop: 20, background: 'linear-gradient(135deg, #0284c7, #0ea5e9)', color: '#ffffff', border: 'none', padding: '12px 24px', borderRadius: 999, fontWeight: 700, fontSize: 14, cursor: 'pointer', boxShadow: '0 4px 14px rgba(2, 132, 199, 0.3)' }}>
            Go to Scanner →
          </button>
        )}
      </div>
    );
  }

  const tlsMod = scan.module_results?.find(m => m.module === 'tls_validation');
  const tlsData = tlsMod?.data || {};

  const { is_expired: isExpired, is_self_signed: isSelfSigned, chain_valid: chainValid, is_untrusted_ca: isUntrustedCa, hostname_matches: hostnameMatches } = tlsData;
  const daysRemaining = tlsData.days_to_expiration ?? tlsData.days_remaining;

  const issuerDisplay = typeof tlsData.issuer === 'object' ? (tlsData.issuer?.organization || tlsData.issuer?.common_name || 'N/A') : (tlsData.issuer || 'N/A');
  const commonNameDisplay = tlsData.common_name || (typeof tlsData.subject === 'object' ? tlsData.subject?.common_name : null) || 'N/A';
  const fingerprintDisplay = tlsData.sha256_fingerprint || tlsData.fingerprint_sha256 || null;
  const sansList = tlsData.subject_alt_names || tlsData.sans || [];
  const isUnavailable = tlsData.status === 'unavailable' || tlsData.status === 'failed' || (!fingerprintDisplay && tlsData.error);

  let statusBadge = { label: 'Valid & Trusted', bg: '#ecfdf5', color: '#059669', border: '#a7f3d0', icon: '✓' };
  if (isUnavailable) statusBadge = { label: 'TLS Handshake Failed / Port 443 Unavailable', bg: '#fff1f2', color: '#e11d48', border: '#fecdd3', icon: '✕' };
  else if (tlsData.is_unverified_fallback) statusBadge = { label: 'Unverified Certificate (Handshake Failed)', bg: '#fffbeb', color: '#d97706', border: '#fde68a', icon: '⚠️' };
  else if (isExpired) statusBadge = { label: 'Expired Certificate', bg: '#fff1f2', color: '#e11d48', border: '#fecdd3', icon: '⚠️' };
  else if (hostnameMatches === false) statusBadge = { label: 'Domain Mismatch', bg: '#fff1f2', color: '#e11d48', border: '#fecdd3', icon: '⚠️' };
  else if (isSelfSigned) statusBadge = { label: 'Self-Signed (Untrusted Root)', bg: '#fffbeb', color: '#d97706', border: '#fde68a', icon: '⚠️' };
  else if (isUntrustedCa || chainValid === false) statusBadge = { label: 'Untrusted CA / Invalid Chain', bg: '#fff1f2', color: '#e11d48', border: '#fecdd3', icon: '⚠️' };
  else if (tlsData.is_not_yet_valid) statusBadge = { label: 'Not Yet Valid', bg: '#fffbeb', color: '#d97706', border: '#fde68a', icon: '⚠️' };

  function handleCopyFingerprint() {
    if (fingerprintDisplay) {
      navigator.clipboard.writeText(fingerprintDisplay);
      setCopiedFingerprint(true);
      setTimeout(() => setCopiedFingerprint(false), 2000);
    }
  }

  const filteredSans = sansList.filter(s => s.toLowerCase().includes(sanSearch.toLowerCase()));
  const subjectObj = tlsData.subject_details || tlsData.subject || {};
  const issuerObj = tlsData.issuer_details || {};
  const cryptoObj = tlsData.cryptography || {};
  const validityObj = tlsData.validity || {};
  const impersonationObj = tlsData.domain_impersonation || {};
  const dimensions = tlsData.security_assessment_dimensions || [];
  const findingsList = tlsData.investigation_findings || [];
  const summaryObj = tlsData.investigation_summary || {};

  const notBeforeStr = tlsData.not_before ? new Date(tlsData.not_before).toLocaleDateString() : 'N/A';
  const notAfterStr = tlsData.not_after ? new Date(tlsData.not_after).toLocaleDateString() : 'N/A';
  const progressPct = validityObj.progress_pct ?? (
    daysRemaining !== null && daysRemaining !== undefined
      ? Math.max(0, Math.min(100, Math.round(((90 - Math.max(0, daysRemaining)) / 90) * 100)))
      : 50
  );

  const verdict = getPlainEnglishVerdict(scan, tlsData, isUnavailable, daysRemaining);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1120, margin: '0 auto', paddingBottom: 48 }}>
      {/* SECTION A: Overview */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>TLS Certificate Intelligence</span>
              <span style={{ background: statusBadge.bg, color: statusBadge.color, border: `1px solid ${statusBadge.border}`, padding: '3px 12px', borderRadius: 999, fontSize: 12, fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <span>{statusBadge.icon}</span> {statusBadge.label}
              </span>
            </div>
            <h2 style={{ fontSize: 24, fontWeight: 800, color: '#0f172a', marginTop: 6, fontFamily: 'IBM Plex Mono, monospace' }}>
              {scan.hostname || scan.target_url}
            </h2>
          </div>

          <div style={{ textAlign: 'right' }}>
            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.05em' }}>Overall Certificate Assessment</span>
            <div style={{ fontSize: 14, fontWeight: 700, marginTop: 4, color: isUnavailable || isExpired || hostnameMatches === false ? '#e11d48' : isSelfSigned ? '#d97706' : '#059669' }}>
              {isUnavailable ? 'Connection Blocked / Offline' : isExpired ? 'Critical Expiration Risk' : hostnameMatches === false ? 'Domain Mismatch Critical' : isSelfSigned ? 'Self-Signed Warning' : 'Publicly Valid & Trusted'}
            </div>
          </div>
        </div>

        {/* Analytical Clarity Alert Callout */}
        <div style={{ marginTop: 18, background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 12, padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 12, fontSize: 12.5, color: '#475569' }}>
          <span style={{ fontSize: 16, color: '#0284c7' }}>ℹ️</span>
          <span><strong>Analytical Principle:</strong> Do not confuse certificate validity with website legitimacy. Attackers frequently issue valid TLS certificates from public Certificate Authorities on dedicated phishing infrastructure.</span>
        </div>

        {tlsData.is_unverified_fallback && (
          <div style={{ marginTop: 14, background: '#fffbeb', border: '1.5px solid #fde68a', borderRadius: 12, padding: '12px 18px', display: 'flex', alignItems: 'center', gap: 12, fontSize: 13, color: '#92400e' }}>
            <span style={{ fontSize: 18 }}>⚠️</span>
            <div>
              <strong>UNVERIFIED RAW CERTIFICATE:</strong> This metadata was extracted via an unverified forensic probe because standard TLS verification failed ({tlsData.chain_error || 'untrusted authority or invalid chain'}). Standard TLS trust handshake did not succeed.
            </div>
          </div>
        )}

        {/* Metrics Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginTop: 20 }}>
          <MetricBox label="Certificate Authority" value={isUnavailable ? 'N/A' : (issuerObj.ca_name || issuerDisplay)} />
          <MetricBox label="Certificate Type" value={isUnavailable ? 'N/A' : (tlsData.certificate_type || 'N/A')} color={tlsData.is_unverified_fallback ? '#d97706' : '#0284c7'} />
          <MetricBox label="Protocol & Version" value={isUnavailable ? 'N/A' : (tlsData.tls_version || tlsData.tls_protocol || 'N/A')} mono />
          <MetricBox label="Expiration Timeline" value={isUnavailable || daysRemaining === null || daysRemaining === undefined ? 'N/A' : `${daysRemaining} days left`} color={(daysRemaining ?? 0) <= 0 ? '#e11d48' : (daysRemaining ?? 0) <= 14 ? '#d97706' : '#059669'} />
        </div>
      </Card>

      {/* SECTION: Layman-Friendly Executive Verdict & Real-World Meaning */}
      <div style={{ background: verdict.cardBg, border: '1.5px solid var(--border-subtle)', borderLeft: `6px solid ${verdict.borderColor}`, borderRadius: 20, padding: '24px 28px', boxShadow: 'var(--shadow-sm)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 16 }}>💡</span>
              <span style={{ fontSize: 11.5, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '.07em', color: verdict.tagColor }}>
                Plain-English Verdict & Real-World Conclusion
              </span>
            </div>
            <h3 style={{ fontSize: 19, fontWeight: 800, color: '#0f172a', marginTop: 6 }}>
              {verdict.headline}
            </h3>
          </div>
          <span style={{ padding: '4px 14px', borderRadius: 999, fontSize: 12, fontWeight: 800, background: verdict.badgeBg, color: verdict.badgeColor, border: `1px solid ${verdict.badgeBorder}`, fontFamily: 'IBM Plex Mono' }}>
            {verdict.badgeText}
          </span>
        </div>

        <p style={{ fontSize: 13.5, color: '#334155', marginTop: 12, lineHeight: 1.6, fontWeight: 500 }}>
          {verdict.explanation}
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12, marginTop: 16 }}>
          <div style={{ background: '#ffffff', padding: '14px 18px', borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '.05em' }}>🌐 What this means for visitors</span>
            <p style={{ fontSize: 12.5, color: '#0f172a', marginTop: 5, lineHeight: 1.5, margin: '4px 0 0' }}>{verdict.impact}</p>
          </div>
          <div style={{ background: '#ffffff', padding: '14px 18px', borderRadius: 12, border: '1px solid #e2e8f0' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '.05em' }}>🛡️ Recommended Action</span>
            <p style={{ fontSize: 12.5, color: verdict.actionColor, marginTop: 5, lineHeight: 1.5, margin: '4px 0 0', fontWeight: 600 }}>{verdict.action}</p>
          </div>
        </div>
      </div>

      {/* SECTION B: Detailed Technical Sections */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))', gap: 20 }}>
        {/* Subject Information */}
        <SubCard>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <span style={{ fontSize: 16 }}>👤</span>
            <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>Subject Information</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
            <InfoRow label="Common Name (CN)" value={isUnavailable ? 'N/A' : commonNameDisplay} mono isStrong />
            <InfoRow label="Organization (O)" value={isUnavailable ? 'N/A' : (subjectObj.organization || 'Not Specified (DV)')} isStrong />
            <InfoRow label="Organizational Unit (OU)" value={isUnavailable ? 'N/A' : (subjectObj.organizational_unit || 'None')} />
            <InfoRow label="Country (C)" value={isUnavailable ? 'N/A' : (subjectObj.country || 'N/A')} isStrong />
            <div style={{ marginTop: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ color: '#64748b', fontWeight: 600 }}>Subject Alternative Names ({isUnavailable ? 0 : sansList.length}):</span>
                {sansList.length > 5 && !isUnavailable && (
                  <input type="text" placeholder="Filter SANs..." value={sanSearch} onChange={e => setSanSearch(e.target.value)} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 6, border: '1px solid #cbd5e1', outline: 'none' }} />
                )}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, maxHeight: 110, overflowY: 'auto' }}>
                {!isUnavailable && filteredSans.length > 0 ? (
                  filteredSans.map((san, idx) => (
                    <span key={idx} style={{ background: '#f0f9ff', color: '#0369a1', border: '1px solid #bae6fd', borderRadius: 6, padding: '2px 8px', fontSize: 11, fontFamily: 'IBM Plex Mono' }}>
                      {san}
                    </span>
                  ))
                ) : (
                  <span style={{ color: '#94a3b8', fontSize: 12 }}>{isUnavailable ? 'Port 443 unavailable — no SANs retrieved' : 'No matching SANs recorded'}</span>
                )}
              </div>
            </div>
          </div>
        </SubCard>

        {/* Issuer Information */}
        <SubCard>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <span style={{ fontSize: 16 }}>🏛️</span>
            <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>Issuer & Authority</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
            <InfoRow label="Certificate Authority" value={isUnavailable ? 'N/A' : (issuerObj.ca_name || issuerDisplay)} color="#0284c7" isStrong />
            <InfoRow label="Issuer Common Name" value={isUnavailable ? 'N/A' : (issuerObj.common_name || 'N/A')} mono isStrong />
            <InfoRow label="Issuer Organization" value={isUnavailable ? 'N/A' : (issuerObj.organization || issuerDisplay)} isStrong />
            <InfoRow label="Issuer Country" value={isUnavailable ? 'N/A' : (issuerObj.country || 'N/A')} />
            <InfoRow label="Trust Anchor Status" value={isUnavailable ? 'N/A (Port 443 Offline)' : (chainValid && !isSelfSigned ? '✓ Public System Trust Store' : isSelfSigned ? '⚠️ Self-Signed (Untrusted)' : '⚠️ Untrusted Chain')} color={isUnavailable ? '#64748b' : (chainValid && !isSelfSigned ? '#059669' : '#e11d48')} isStrong />
          </div>
        </SubCard>

        {/* Validity & Visual Timeline */}
        <SubCard>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <span style={{ fontSize: 16 }}>⏳</span>
            <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>Validity & Lifecycle Timeline</h3>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 16 }}>
            <div>
              <span style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>Issued (notBefore)</span>
              <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 3 }}>{isUnavailable ? 'N/A' : notBeforeStr}</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <span style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>Lifespan Status</span>
              <div style={{ fontWeight: 800, color: isUnavailable ? '#64748b' : isExpired ? '#e11d48' : '#0284c7', marginTop: 3 }}>
                {isUnavailable ? 'N/A' : isExpired ? 'EXPIRED' : `${daysRemaining ?? 'N/A'} days left`}
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <span style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', fontWeight: 700 }}>Expires (notAfter)</span>
              <div style={{ fontWeight: 700, color: '#0f172a', marginTop: 3 }}>{isUnavailable ? 'N/A' : notAfterStr}</div>
            </div>
          </div>
          <div>
            <div style={{ height: 8, background: '#f1f5f9', borderRadius: 999, overflow: 'hidden' }}>
              <div style={{ width: `${isUnavailable ? 0 : progressPct}%`, height: '100%', background: isExpired ? '#e11d48' : progressPct > 80 ? '#d97706' : '#0284c7', transition: 'width 0.4s ease' }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#64748b', marginTop: 6 }}>
              <span>Issued</span>
              <span>{isUnavailable ? 'Unavailable / Offline' : `Currently Valid (${progressPct}% elapsed)`}</span>
              <span>Expiration</span>
            </div>
          </div>
        </SubCard>

        {/* Cryptographic Specifications */}
        <SubCard>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 16 }}>🔐</span>
              <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>Cryptographic Specifications</h3>
            </div>
            <button onClick={() => setShowRawDetails(!showRawDetails)} style={{ background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: 6, padding: '4px 10px', fontSize: 11.5, fontWeight: 600, color: '#0284c7', cursor: 'pointer' }}>
              {showRawDetails ? 'Hide Raw Details' : 'Expand Raw Details'}
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10, fontSize: 12.5 }}>
            <MetricBox label="Public Key" value={isUnavailable ? 'N/A' : (cryptoObj.public_key_algorithm ? `${cryptoObj.public_key_algorithm} (${cryptoObj.public_key_size || 'N/A'}-bit)` : 'N/A')} />
            <MetricBox label="Cipher Suite" value={isUnavailable ? 'N/A' : (tlsData.cipher_suite || 'N/A')} mono />
            <MetricBox label="Signature Algorithm" value={isUnavailable ? 'N/A' : (cryptoObj.signature_algorithm || tlsData.signature_algorithm || 'N/A')} />
            <MetricBox label="Serial Number" value={isUnavailable ? 'N/A' : (tlsData.serial_number || 'N/A')} mono />
          </div>

          {/* SHA-256 Fingerprint */}
          <div style={{ marginTop: 12, background: '#f0f9ff', padding: '10px 14px', borderRadius: 8, border: '1px solid #bae6fd' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#0369a1', textTransform: 'uppercase' }}>SHA-256 Certificate Fingerprint</span>
              <button onClick={handleCopyFingerprint} style={{ background: copiedFingerprint ? '#059669' : '#0284c7', color: '#ffffff', border: 'none', borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600, cursor: 'pointer' }}>
                {copiedFingerprint ? '✓ Copied' : '📋 Copy'}
              </button>
            </div>
            <div style={{ fontSize: 12, fontFamily: 'IBM Plex Mono, monospace', color: '#0369a1', wordBreak: 'break-all', marginTop: 4 }}>
              {fingerprintDisplay || 'No fingerprint recorded'}
            </div>
          </div>

          {showRawDetails && (
            <div style={{ marginTop: 12, background: '#0f172a', color: '#38bdf8', padding: 12, borderRadius: 8, fontSize: 11, fontFamily: 'IBM Plex Mono', maxHeight: 180, overflowY: 'auto' }}>
              <pre>{JSON.stringify(tlsData, null, 2)}</pre>
            </div>
          )}
        </SubCard>
      </div>

      {/* SECTION 3: 7-Dimension Security Assessment */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>Rigorous Evaluation</span>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>Certificate Security Assessment</h3>
          </div>
          <span style={{ fontSize: 12, color: '#64748b' }}>7 Independent Risk Dimensions</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {dimensions.map((dim, idx) => {
            const isPass = dim.status === 'pass', isWarning = dim.status === 'warning', isFail = dim.status === 'fail';
            const statusBg = isPass ? '#ecfdf5' : isWarning ? '#fffbeb' : isFail ? '#fff1f2' : '#f8fafc';
            const statusColor = isPass ? '#059669' : isWarning ? '#d97706' : isFail ? '#e11d48' : '#64748b';
            const statusBorder = isPass ? '#a7f3d0' : isWarning ? '#fde68a' : isFail ? '#fecdd3' : '#e2e8f0';
            const isExpanded = expandedDim === dim.id;

            return (
              <div key={dim.id || idx} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 12, padding: '14px 18px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{ background: statusBg, color: statusColor, border: `1px solid ${statusBorder}`, padding: '3px 10px', borderRadius: 999, fontSize: 11, fontWeight: 800, textTransform: 'uppercase', fontFamily: 'IBM Plex Mono' }}>
                      {dim.status.toUpperCase()}
                    </span>
                    <strong style={{ fontSize: 14, color: '#0f172a' }}>{dim.name}</strong>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    {dim.severity && dim.severity !== 'info' && (
                      <span style={{ fontSize: 10.5, fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: dim.severity === 'critical' ? '#e11d48' : '#ea580c', color: '#ffffff', textTransform: 'uppercase' }}>
                        {dim.severity}
                      </span>
                    )}
                    <button onClick={() => setExpandedDim(isExpanded ? null : dim.id)} style={{ background: 'none', border: 'none', color: '#0284c7', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>
                      {isExpanded ? 'Hide Evidence ▲' : 'View Evidence ▼'}
                    </button>
                  </div>
                </div>

                <p style={{ fontSize: 13, color: '#475569', margin: 0, lineHeight: 1.45 }}>{dim.explanation}</p>

                {isExpanded && dim.evidence && (
                  <div style={{ marginTop: 6, background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: 8, padding: 10, fontSize: 11.5, fontFamily: 'IBM Plex Mono', color: '#0369a1' }}>
                    <pre style={{ margin: 0 }}>{JSON.stringify(dim.evidence, null, 2)}</pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Card>

      {/* SECTION 4: Domain Identity & Brand Impersonation */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>Brand Integrity & Deception Analysis</span>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>Domain Identity & Brand Impersonation</h3>
          </div>
          <span style={{ background: impersonationObj.brand_detected && !impersonationObj.is_official_domain ? '#fff1f2' : '#ecfdf5', color: impersonationObj.brand_detected && !impersonationObj.is_official_domain ? '#e11d48' : '#059669', border: `1px solid ${impersonationObj.brand_detected && !impersonationObj.is_official_domain ? '#fecdd3' : '#a7f3d0'}`, padding: '4px 12px', borderRadius: 999, fontSize: 12, fontWeight: 700 }}>
            {impersonationObj.brand_detected && !impersonationObj.is_official_domain ? '⚠️ Brand Match Detected' : '✓ No Brand Impersonation Detected'}
          </span>
        </div>

        <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 12, padding: '12px 18px', marginBottom: 16, fontSize: 12.5, color: '#334155', lineHeight: 1.5 }}>
          <strong>Investigative Caution:</strong> A brand name appearing inside a domain name or certificate is a potential impersonation indicator, but is <em>not sufficient evidence of phishing on its own</em>. Defensive security analysts must evaluate the full infrastructure context.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14, fontSize: 13 }}>
          <MetricBox label="Detected Brand Keyword" value={impersonationObj.brand_detected ? impersonationObj.brand_detected.toUpperCase() : 'None (No brand targeted)'} color={impersonationObj.brand_detected ? '#0284c7' : '#0f172a'} />
          <MetricBox label="Official Brand Status" value={impersonationObj.is_official_domain ? 'Verified Official Domain' : 'Unverified Third-Party / Mimic'} color={impersonationObj.is_official_domain ? '#059669' : '#e11d48'} />
          <MetricBox label="Suspicious Affixes" value={impersonationObj.suspicious_affixes?.length > 0 ? impersonationObj.suspicious_affixes.join(', ') : 'None detected'} />
          <MetricBox label="Punycode / Homoglyphs" value={impersonationObj.is_punycode ? '⚠️ Punycode Present' : '✓ Standard ASCII Domain'} color={impersonationObj.is_punycode ? '#e11d48' : '#059669'} />
        </div>
      </Card>

      {/* SECTION 5: Certificate Transparency & Historical Intel */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>Public Logging & Drift</span>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>Certificate Transparency & Historical Intelligence</h3>
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
      </Card>

      {/* SECTION 6: Investigation Findings */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>Actionable Evidence</span>
            <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>Investigation Findings ({findingsList.length})</h3>
          </div>
          <span style={{ fontSize: 12, color: '#64748b' }}>Analyst Observations</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {findingsList.map((f, idx) => {
            const isHigh = f.severity === 'critical' || f.severity === 'high', isMed = f.severity === 'medium';
            const badgeColor = isHigh ? '#e11d48' : isMed ? '#d97706' : '#0284c7';
            const badgeBg = isHigh ? '#fff1f2' : isMed ? '#fffbeb' : '#f0f9ff';

            return (
              <div key={idx} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 12, padding: '16px 20px', borderLeft: `4px solid ${badgeColor}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                  <h4 style={{ fontSize: 14.5, fontWeight: 800, color: '#0f172a' }}>{f.title}</h4>
                  <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', padding: '2px 8px', borderRadius: 4, background: badgeBg, color: badgeColor, border: `1px solid ${badgeColor}33` }}>
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
      </Card>

      {/* SECTION 7: Investigation Summary (3 Dimensions) */}
      <Card>
        <div style={{ marginBottom: 18 }}>
          <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>Final Synthesized Posture</span>
          <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>Investigation Summary</h3>
          <p style={{ fontSize: 12.5, color: '#64748b', marginTop: 2 }}>
            Separates technical cryptographic hygiene from domain authenticity and malicious threat indicators.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          {[
            { key: 'certificate_health', num: 1, title: 'Certificate Health', defSummary: 'Technical certificate configuration, cryptographic parameters, and chain validation.', okStatus: 'Healthy' },
            { key: 'domain_identity', num: 2, title: 'Domain Identity', defSummary: 'Alignment between certificate identity, SAN coverage, and target domain.', okStatus: 'Aligned' },
            { key: 'website_trust', num: 3, title: 'Website Trust', defSummary: 'Impersonation heuristics and brand mimicry indicators.', okStatus: 'Neutral / Standard' },
          ].map(dim => {
            const dimObj = summaryObj[dim.key] || {};
            const isOk = !isUnavailable && dimObj.status === dim.okStatus;
            const isNeutral = isUnavailable || dimObj.status?.includes('Offline') || dimObj.status?.includes('Inert') || dimObj.status?.includes('Unresolvable');
            const statusColor = isOk ? '#059669' : isNeutral ? '#64748b' : '#e11d48';
            const displayStatus = dimObj.status || (isUnavailable ? 'Offline / N/A' : dim.okStatus);
            const displaySummary = dimObj.summary || (isUnavailable ? 'Host did not respond on port 443; no active certificate could be analyzed.' : dim.defSummary);
            const displayDetails = dimObj.details || (isUnavailable ? 'Port 443 unreachable' : 'Telemetry recorded');

            return (
              <div key={dim.key} style={{ background: '#f8fafc', border: '1.5px solid #e2e8f0', borderRadius: 14, padding: '18px 20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Dimension {dim.num}</span>
                    <span style={{ fontSize: 12, fontWeight: 800, color: statusColor, fontFamily: 'IBM Plex Mono' }}>
                      {displayStatus}
                    </span>
                  </div>
                  <h4 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', marginTop: 8 }}>{dim.title}</h4>
                  <p style={{ fontSize: 12.5, color: '#475569', marginTop: 4, lineHeight: 1.45 }}>
                    {displaySummary}
                  </p>
                </div>
                <div style={{ fontSize: 11.5, color: isNeutral ? '#64748b' : '#0284c7', marginTop: 12, fontFamily: 'IBM Plex Mono' }}>
                  {displayDetails}
                </div>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}
