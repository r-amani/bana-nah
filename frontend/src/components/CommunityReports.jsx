import React, { useState, useEffect } from 'react';

const CATEGORIES = [
  { id: 'phishing', label: 'Phishing' },
  { id: 'malware', label: 'Malware' },
  { id: 'scam', label: 'Scam' },
  { id: 'spam', label: 'Spam' },
  { id: 'defacement', label: 'Defacement' },
  { id: 'c2_server', label: 'C2 Server' },
  { id: 'data_exfiltration', label: 'Data Exfiltration' },
  { id: 'other', label: 'Other' },
];

export default function CommunityReports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('all');

  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [newUrl, setNewUrl] = useState('');
  const [newCategory, setNewCategory] = useState('phishing');
  const [newDesc, setNewDesc] = useState('');
  const [newContact, setNewContact] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState(null);

  useEffect(() => {
    fetchReports();
  }, [statusFilter]);

  async function fetchReports() {
    setLoading(true);
    try {
      const url = statusFilter === 'all' ? '/api/reports' : `/api/reports?status=${statusFilter}`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setReports(data);
      }
    } catch (e) {
      console.warn('Error fetching reports:', e);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreateReport(e) {
    e.preventDefault();
    if (!newUrl.trim() || newDesc.trim().length < 10) return;

    setSubmitting(true);
    setFeedback(null);

    try {
      const res = await fetch('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: newUrl.trim(),
          category: newCategory,
          description: newDesc.trim(),
          reporter_contact: newContact.trim() || null,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to submit report');
      }

      setFeedback({ type: 'success', message: 'Report submitted successfully for analyst moderation!' });
      setNewUrl('');
      setNewDesc('');
      setNewContact('');
      setShowSubmitModal(false);
      fetchReports();
    } catch (err) {
      setFeedback({ type: 'error', message: err.message });
    } finally {
      setSubmitting(false);
    }
  }

  async function updateReportStatus(reportId, newStatus) {
    try {
      const res = await fetch(`/api/reports/${reportId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: newStatus,
          reviewer_notes: `Status updated to ${newStatus} by analyst via console.`,
        }),
      });
      if (res.ok) {
        fetchReports();
      }
    } catch (e) {
      console.warn('Error patching report:', e);
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1100, margin: '0 auto' }}>
      {/* Header Bar */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 16,
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div>
          <span style={{ fontSize: 12, color: '#0284c7', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>
            🚩 Community Threat Intelligence
          </span>
          <h2 style={{ fontSize: 24, fontWeight: 800, color: '#0f172a', marginTop: 4 }}>
            Crowdsourced Threat Reports & Moderation
          </h2>
          <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
            Community reports are tracked, de-duplicated, and moderated to provide evidence-backed crowd signals.
          </p>
        </div>

        <button
          onClick={() => setShowSubmitModal(!showSubmitModal)}
          style={{
            background: 'linear-gradient(135deg, #0284c7, #0ea5e9)',
            border: 'none',
            color: '#ffffff',
            padding: '12px 22px',
            borderRadius: 999,
            fontSize: 14,
            fontWeight: 700,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            boxShadow: '0 4px 14px rgba(2, 132, 199, 0.3)',
          }}
        >
          + Submit Threat Report
        </button>
      </div>

      {feedback && (
        <div style={{
          background: feedback.type === 'success' ? '#ecfdf5' : '#fff1f2',
          border: `1px solid ${feedback.type === 'success' ? '#a7f3d0' : '#fecdd3'}`,
          color: feedback.type === 'success' ? '#059669' : '#e11d48',
          padding: 16,
          borderRadius: 14,
          fontSize: 13,
          fontWeight: 600,
        }}>
          {feedback.message}
        </div>
      )}

      {/* Submission Modal Form */}
      {showSubmitModal && (
        <div style={{
          background: '#ffffff',
          borderRadius: 20,
          border: '1.5px solid #bae6fd',
          padding: '26px 30px',
          boxShadow: 'var(--shadow-md)',
        }}>
          <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginBottom: 16 }}>
            Submit Suspicious Domain or Phishing URL
          </h3>
          <form onSubmit={handleCreateReport} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 700, color: '#475569', display: 'block', marginBottom: 6 }}>
                Target URL
              </label>
              <input
                type="text"
                placeholder="https://malicious-login.xyz/auth"
                value={newUrl}
                onChange={e => setNewUrl(e.target.value)}
                required
                style={{
                  width: '100%',
                  background: '#f8fafc',
                  color: '#0f172a',
                  border: '1.5px solid #cbd5e1',
                  padding: '10px 14px',
                  borderRadius: 10,
                  fontSize: 13,
                  fontFamily: 'IBM Plex Mono',
                  outline: 'none',
                }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 700, color: '#475569', display: 'block', marginBottom: 6 }}>
                  Threat Category
                </label>
                <select
                  value={newCategory}
                  onChange={e => setNewCategory(e.target.value)}
                  style={{
                    width: '100%',
                    background: '#f8fafc',
                    color: '#0f172a',
                    border: '1.5px solid #cbd5e1',
                    padding: '10px 14px',
                    borderRadius: 10,
                    fontSize: 13,
                    outline: 'none',
                  }}
                >
                  {CATEGORIES.map(c => (
                    <option key={c.id} value={c.id}>{c.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: 12, fontWeight: 700, color: '#475569', display: 'block', marginBottom: 6 }}>
                  Reporter Contact (Optional)
                </label>
                <input
                  type="text"
                  placeholder="analyst@security.org"
                  value={newContact}
                  onChange={e => setNewContact(e.target.value)}
                  style={{
                    width: '100%',
                    background: '#f8fafc',
                    color: '#0f172a',
                    border: '1.5px solid #cbd5e1',
                    padding: '10px 14px',
                    borderRadius: 10,
                    fontSize: 13,
                    outline: 'none',
                  }}
                />
              </div>
            </div>

            <div>
              <label style={{ fontSize: 12, fontWeight: 700, color: '#475569', display: 'block', marginBottom: 6 }}>
                Description & Observable Evidence (Min 10 characters)
              </label>
              <textarea
                placeholder="Observed fake bank login page harvesting account numbers and OTPs..."
                value={newDesc}
                onChange={e => setNewDesc(e.target.value)}
                rows={3}
                required
                style={{
                  width: '100%',
                  background: '#f8fafc',
                  color: '#0f172a',
                  border: '1.5px solid #cbd5e1',
                  padding: '10px 14px',
                  borderRadius: 10,
                  fontSize: 13,
                  outline: 'none',
                  lineHeight: 1.5,
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
              <button
                type="button"
                onClick={() => setShowSubmitModal(false)}
                style={{
                  background: '#f8fafc',
                  border: '1.5px solid #cbd5e1',
                  color: '#64748b',
                  padding: '9px 18px',
                  borderRadius: 999,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                style={{
                  background: 'linear-gradient(135deg, #0284c7, #0ea5e9)',
                  border: 'none',
                  color: '#ffffff',
                  padding: '9px 24px',
                  borderRadius: 999,
                  fontSize: 13.5,
                  fontWeight: 700,
                  cursor: 'pointer',
                  boxShadow: '0 3px 10px rgba(2, 132, 199, 0.28)',
                }}
              >
                {submitting ? 'Submitting...' : 'Submit Report'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Reports Feed */}
      <div style={{
        background: '#ffffff',
        borderRadius: 20,
        border: '1.5px solid var(--border-subtle)',
        padding: '26px 30px',
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
          <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a' }}>
            Submitted Reports Feed ({reports.length})
          </h3>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {['all', 'pending', 'verified', 'rejected', 'under_review'].map(status => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                style={{
                  background: statusFilter === status ? '#0284c7' : '#f8fafc',
                  color: statusFilter === status ? '#ffffff' : '#64748b',
                  border: `1.5px solid ${statusFilter === status ? '#0284c7' : '#e2e8f0'}`,
                  padding: '5px 13px',
                  borderRadius: 999,
                  fontSize: 11.5,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div style={{ padding: 48, textAlign: 'center', color: '#0284c7', fontWeight: 600 }}>
            Loading community reports...
          </div>
        ) : reports.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: '#94a3b8' }}>
            No community reports found. Use the button above to submit the first report.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {reports.map(rep => {
              const isVerified = rep.status === 'verified' || rep.status === 'corroborated';
              const isRejected = rep.status === 'rejected';

              return (
                <div
                  key={rep.report_id}
                  style={{
                    background: '#f8fafc',
                    borderRadius: 14,
                    border: '1px solid #e2e8f0',
                    padding: 18,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{
                          fontSize: 10.5,
                          fontWeight: 800,
                          padding: '3px 8px',
                          borderRadius: 6,
                          background: isVerified ? '#ecfdf5' : isRejected ? '#f1f5f9' : '#fefce8',
                          color: isVerified ? '#059669' : isRejected ? '#64748b' : '#d97706',
                          border: `1px solid ${isVerified ? '#a7f3d0' : isRejected ? '#cbd5e1' : '#fef08a'}`,
                          textTransform: 'uppercase',
                        }}>
                          {rep.status}
                        </span>
                        <span style={{
                          fontSize: 10.5,
                          fontWeight: 700,
                          padding: '3px 8px',
                          borderRadius: 6,
                          background: '#e0f2fe',
                          color: '#0369a1',
                          border: '1px solid #bae6fd',
                          textTransform: 'uppercase',
                        }}>
                          {rep.category}
                        </span>
                      </div>
                      <h4 style={{ fontSize: 14, fontWeight: 700, color: '#0f172a', marginTop: 8, fontFamily: 'IBM Plex Mono' }}>
                        {rep.url}
                      </h4>
                    </div>

                    {/* Moderation Actions */}
                    <div style={{ display: 'flex', gap: 10 }}>
                      {rep.status !== 'verified' && (
                        <button
                          onClick={() => updateReportStatus(rep.report_id, 'verified')}
                          style={{
                            background: '#ecfdf5',
                            color: '#059669',
                            border: '1px solid #a7f3d0',
                            padding: '5px 13px',
                            borderRadius: 999,
                            fontSize: 11.5,
                            fontWeight: 700,
                            cursor: 'pointer',
                          }}
                        >
                          ✓ Corroborate
                        </button>
                      )}
                      {rep.status !== 'rejected' && (
                        <button
                          onClick={() => updateReportStatus(rep.report_id, 'rejected')}
                          style={{
                            background: '#fff1f2',
                            color: '#e11d48',
                            border: '1px solid #fecdd3',
                            padding: '5px 13px',
                            borderRadius: 999,
                            fontSize: 11.5,
                            fontWeight: 700,
                            cursor: 'pointer',
                          }}
                        >
                          ✕ Reject
                        </button>
                      )}
                    </div>
                  </div>

                  <p style={{ fontSize: 13, color: '#334155', marginTop: 8, lineHeight: 1.5 }}>
                    {rep.description}
                  </p>

                  <div style={{ fontSize: 11.5, color: '#64748b', marginTop: 8, fontFamily: 'IBM Plex Mono' }}>
                    Report ID: {rep.report_id} • Submitted: {new Date(rep.created_at).toLocaleString()}
                    {rep.reviewer_notes && ` • Note: ${rep.reviewer_notes}`}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
