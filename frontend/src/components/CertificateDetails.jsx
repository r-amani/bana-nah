import React from 'react';

export default function CertificateDetails({ scan }) {
  if (!scan) {
    return (
      <div style={{ textAlign: 'center', padding: 60, background: '#151d30', borderRadius: 14, border: '1px solid #23304c' }}>
        <h3 style={{ fontSize: 18, color: '#f8fafc' }}>No Target Analyzed</h3>
        <p style={{ color: '#94a3b8', marginTop: 8 }}>Execute a scan to inspect TLS certificate parameters.</p>
      </div>
    );
  }

  // Find TLS validation module result
  const tlsMod = scan.module_results?.find(m => m.module === 'tls_validation');
  const tlsData = tlsMod?.data || {};

  const isExpired = tlsData.is_expired;
  const isSelfSigned = tlsData.is_self_signed;
  const matchesHostname = tlsData.hostname_matches;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1000, margin: '0 auto' }}>
      <div style={{
        background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <span style={{ fontSize: 12, color: '#94a3b8', textTransform: 'uppercase' }}>Cryptography & Trust</span>
            <h2 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', marginTop: 4 }}>
              TLS Certificate Inspection: {scan.hostname}
            </h2>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            {isSelfSigned ? (
              <span style={{
                background: 'rgba(244, 63, 94, 0.15)', color: '#fda4af', border: '1px solid rgba(244, 63, 94, 0.4)',
                padding: '4px 12px', borderRadius: 6, fontSize: 12, fontWeight: 700,
              }}>
                ⚠️ Self-Signed Certificate
              </span>
            ) : (
              <span style={{
                background: 'rgba(16, 185, 129, 0.15)', color: '#6ee7b7', border: '1px solid rgba(16, 185, 129, 0.4)',
                padding: '4px 12px', borderRadius: 6, fontSize: 12, fontWeight: 700,
              }}>
                ✓ CA-Issued Certificate
              </span>
            )}
            {isExpired && (
              <span style={{
                background: 'rgba(244, 63, 94, 0.15)', color: '#fda4af', border: '1px solid rgba(244, 63, 94, 0.4)',
                padding: '4px 12px', borderRadius: 6, fontSize: 12, fontWeight: 700,
              }}>
                Expired
              </span>
            )}
          </div>
        </div>

        {/* Certificate Parameters Grid */}
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: 16, marginTop: 24,
        }}>
          <div style={{ background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c' }}>
            <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Subject Common Name (CN)</span>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc', marginTop: 6, fontFamily: 'JetBrains Mono' }}>
              {tlsData.common_name || 'N/A'}
            </div>
          </div>

          <div style={{ background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c' }}>
            <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Issuer Authority</span>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc', marginTop: 6 }}>
              {tlsData.issuer || 'N/A'}
            </div>
          </div>

          <div style={{ background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c' }}>
            <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Protocol & Cipher Suite</span>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#38bdf8', marginTop: 6, fontFamily: 'JetBrains Mono' }}>
              {tlsData.tls_version || 'TLSv1.3'} • {tlsData.cipher_suite || 'AES_256_GCM'}
            </div>
          </div>

          <div style={{ background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c' }}>
            <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Validity Window</span>
            <div style={{ fontSize: 12, color: '#cbd5e1', marginTop: 6 }}>
              <div><strong>Not Before:</strong> {tlsData.not_before || 'N/A'}</div>
              <div><strong>Not After:</strong> {tlsData.not_after || 'N/A'}</div>
              <div><strong>Days Remaining:</strong> {tlsData.days_to_expiration ?? 'N/A'} days</div>
            </div>
          </div>
        </div>

        {/* SHA-256 Fingerprint */}
        <div style={{
          background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c', marginTop: 16,
        }}>
          <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>SHA-256 Certificate Fingerprint</span>
          <div style={{
            fontSize: 13, color: '#a78bfa', fontFamily: 'JetBrains Mono', wordBreak: 'break-all', marginTop: 6,
          }}>
            {tlsData.sha256_fingerprint || 'No fingerprint recorded'}
          </div>
        </div>

        {/* Subject Alternative Names (SANs) */}
        <div style={{
          background: '#0c101c', padding: 16, borderRadius: 10, border: '1px solid #23304c', marginTop: 16,
        }}>
          <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>
            Subject Alternative Names (SANs) ({tlsData.subject_alt_names?.length || 0})
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 10 }}>
            {tlsData.subject_alt_names?.length > 0 ? (
              tlsData.subject_alt_names.map((san, i) => (
                <span
                  key={i}
                  style={{
                    background: '#151d30', border: '1px solid #23304c', color: '#e2e8f0',
                    padding: '4px 10px', borderRadius: 6, fontSize: 12, fontFamily: 'JetBrains Mono',
                  }}
                >
                  {san}
                </span>
              ))
            ) : (
              <span style={{ color: '#64748b', fontSize: 12 }}>No SAN entries detected</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
