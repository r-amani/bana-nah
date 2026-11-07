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

  // Submit report form state
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1050, margin: '0 auto' }}>
      {/* Header Bar */}
      <div style={{
        background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24,
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16,
      }}>
        <div>
          <span style={{ fontSize: 12, color: '#f43f5e', fontWeight: 700, textTransform: 'uppercase' }}>
            🚩 Community Threat Intelligence
          </span>
          <h2 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', marginTop: 4 }}>
            Crowdsourced Threat Reports & Moderation
          </h2>
          <p style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
            Community reports are tracked, de-duplicated, and moderated to provide evidence-backed crowd signals.
          </p>
        </div>

        <button
          onClick={() => setShowSubmitModal(!showSubmitModal)}
          style={{
            background: 'linear-gradient(135deg, #f43f5e, #f97316)', border: 'none',
            color: '#fff', padding: '10px 18px', borderRadius: 8, fontSize: 13, fontWeight: 700,
            cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
          }}
        >
          + Submit Threat Report
        </button>
      </div>

      {feedback && (
        <div style={{
          background: feedback.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
          color: feedback.type === 'success' ? '#6ee7b7' : '#fda4af',
          padding: 14, borderRadius: 10,
        }}>
          {feedback.message}
        </div>
      )}

      {/* Submission Modal Form */}
      {showSubmitModal && (
        <div style={{ background: '#151d30', borderRadius: 14, border: '1px solid #6366f1', padding: 24 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc', marginBottom: 14 }}>
            Submit Suspicious Domain or Phishing URL
          </h3>
          <form onSubmit={handleCreateReport} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ fontSize: 12, color: '#94a3b8', display: 'block', marginBottom: 4 }}>Target URL</label>
              <input
                type="text"
                placeholder="https://malicious-login.xyz/auth"
                value={newUrl}
                onChange={e => setNewUrl(e.target.value)}
                required
                style={{
                  width: '100%', background: '#0a0d14', color: '#f8fafc', border: '1px solid #23304c',
                  padding: '10px 14px', borderRadius: 8, fontSize: 13, fontFamily: 'JetBrains Mono',
                }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
              <div>
                <label style={{ fontSize: 12, color: '#94a3b8', display: 'block', marginBottom: 4 }}>Threat Category</label>
                <select
                  value={newCategory}
                  onChange={e => setNewCategory(e.target.value)}
                  style={{
                    width: '100%', background: '#0a0d14', color: '#f8fafc', border: '1px solid #23304c',
                    padding: '10px 14px', borderRadius: 8, fontSize: 13,
                  }}
                >
                  {CATEGORIES.map(c => (
                    <option key={c.id} value={c.id}>{c.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: 12, color: '#94a3b8', display: 'block', marginBottom: 4 }}>Reporter Contact (Optional)</label>
                <input
                  type="text"
                  placeholder="analyst@security.org"
                  value={newContact}
                  onChange={e => setNewContact(e.target.value)}
                  style={{
                    width: '100%', background: '#0a0d14', color: '#f8fafc', border: '1px solid #23304c',
                    padding: '10px 14px', borderRadius: 8, fontSize: 13,
                  }}
                />
              </div>
            </div>

            <div>
              <label style={{ fontSize: 12, color: '#94a3b8', display: 'block', marginBottom: 4 }}>Description & Observable Evidence (Min 10 chars)</label>
              <textarea
                placeholder="Observed fake bank login page harvesting account numbers and OTPs..."
                value={newDesc}
                onChange={e => setNewDesc(e.target.value)}
                rows={3}
                required
                style={{
                  width: '100%', background: '#0a0d14', color: '#f8fafc', border: '1px solid #23304c',
                  padding: '10px 14px', borderRadius: 8, fontSize: 13,
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                onClick={() => setShowSubmitModal(false)}
                style={{
                  background: 'transparent', border: '1px solid #23304c', color: '#94a3b8',
                  padding: '8px 16px', borderRadius: 8, fontSize: 13, cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                style={{
                  background: '#6366f1', border: 'none', color: '#fff',
                  padding: '8px 20px', borderRadius: 8, fontSize: 13, fontWeight: 700, cursor: 'pointer',
                }}
              >
                {submitting ? 'Submitting...' : 'Submit Report'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Reports Feed */}
      <div style={{ background: '#151d30', borderRadius: 14, border: '1px solid #23304c', padding: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>
            Submitted Reports Feed ({reports.length})
          </h3>

          <div style={{ display: 'flex', gap: 6 }}>
            {['all', 'pending', 'verified', 'rejected', 'under_review'].map(status => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                style={{
                  background: statusFilter === status ? '#23304c' : 'transparent',
                  color: statusFilter === status ? '#f8fafc' : '#94a3b8',
                  border: '1px solid #23304c',
                  padding: '4px 10px',
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  cursor: 'pointer',
                }}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#38bdf8' }}>Loading community reports...</div>
        ) : reports.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
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
                    background: '#0c101c', borderRadius: 10, border: '1px solid #23304c', padding: 16,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{
                          fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4,
                          background: isVerified ? 'rgba(16, 185, 129, 0.15)' : isRejected ? 'rgba(100, 116, 139, 0.2)' : 'rgba(245, 158, 11, 0.15)',
                          color: isVerified ? '#6ee7b7' : isRejected ? '#94a3b8' : '#fde68a',
                          textTransform: 'uppercase',
                        }}>
                          {rep.status}
                        </span>
                        <span style={{
                          fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                          background: 'rgba(99, 102, 241, 0.15)', color: '#a5b4fc', textTransform: 'uppercase',
                        }}>
                          {rep.category}
                        </span>
                      </div>
                      <h4 style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc', marginTop: 8, fontFamily: 'JetBrains Mono' }}>
                        {rep.url}
                      </h4>
                    </div>

                    {/* Moderation Actions */}
                    <div style={{ display: 'flex', gap: 6 }}>
                      {rep.status !== 'verified' && (
                        <button
                          onClick={() => updateReportStatus(rep.report_id, 'verified')}
                          style={{
                            background: '#064e3b', color: '#6ee7b7', border: 'none',
                            padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, cursor: 'pointer',
                          }}
                        >
                          ✓ Corroborate
                        </button>
                      )}
                      {rep.status !== 'rejected' && (
                        <button
                          onClick={() => updateReportStatus(rep.report_id, 'rejected')}
                          style={{
                            background: '#4c0519', color: '#fda4af', border: 'none',
                            padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, cursor: 'pointer',
                          }}
                        >
                          ✕ Reject
                        </button>
                      )}
                    </div>
                  </div>

                  <p style={{ fontSize: 12, color: '#cbd5e1', marginTop: 8, lineHeight: 1.5 }}>
                    {rep.description}
                  </p>

                  <div style={{ fontSize: 11, color: '#64748b', marginTop: 8 }}>
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
