import { requireAuthPage } from './auth.js';
import { initNavigation } from './navigation.js';
import { apiRequest } from './api.js';
import { escapeHtml, renderRiskDial, renderRiskBadge, formatDate, showConfirmModal, showToast } from './ui-utils.js';

document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuthPage();
  if (!user) return;

  await initNavigation();

  const scanId = new URLSearchParams(window.location.search).get('id');
  if (!scanId) {
    window.location.href = '/history.html';
    return;
  }

  const container = document.getElementById('scan-details-content');
  const printBtn = document.getElementById('print-report-btn');
  const deleteBtn = document.getElementById('delete-scan-btn');

  if (printBtn) {
    printBtn.addEventListener('click', () => {
      window.print();
    });
  }

  if (deleteBtn) {
    deleteBtn.addEventListener('click', () => {
      showConfirmModal({
        title: 'Delete Scan Record',
        message: 'Are you sure you want to delete this scan from your history? This action cannot be undone.',
        confirmText: 'Delete Scan',
        onConfirm: async () => {
          try {
            await apiRequest(`/scans/${scanId}`, { method: 'DELETE' });
            showToast('Scan deleted successfully', 'success');
            setTimeout(() => {
              window.location.href = '/history.html';
            }, 800);
          } catch (err) {
            showToast(err.message || 'Failed to delete scan', 'error');
          }
        },
      });
    });
  }

  try {
    const res = await apiRequest(`/scans/${scanId}`);
    const scan = res.scan;

    document.getElementById('report-scan-id').textContent = scan.id;
    document.getElementById('report-timestamp').textContent = formatDate(scan.analyzed_at);
    document.getElementById('report-hostname').textContent = scan.normalized_hostname;
    document.getElementById('report-domain').textContent = scan.registrable_domain || 'N/A';
    document.getElementById('report-redacted-url').textContent = scan.submitted_url_redacted;
    document.getElementById('report-confidence').textContent = scan.confidence_level;
    document.getElementById('report-ruleset').textContent = `v${scan.ruleset_version}`;

    // Risk Dial
    document.getElementById('report-risk-dial').innerHTML = renderRiskDial(scan.risk_score, scan.risk_category);

    // Findings
    const findingsList = document.getElementById('report-findings-list');
    if (scan.findings.length === 0) {
      findingsList.innerHTML = '<p style="color: var(--risk-low); font-weight: 600;">✅ No major red flags detected in URL structure.</p>';
    } else {
      findingsList.innerHTML = scan.findings.map(f => `
        <div class="finding-item ${escapeHtml(f.severity)}">
          <div class="finding-header">
            <span class="finding-title">${escapeHtml(f.title)}</span>
            <span class="badge badge-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
          </div>
          <div class="finding-evidence"><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</div>
          <p class="finding-meta">${escapeHtml(f.explanation)}</p>
          <p style="font-size: 0.85rem; color: var(--text-muted);"><strong style="color: var(--text-secondary);">Why it matters:</strong> ${escapeHtml(f.whyItMatters)}</p>
          <div style="background-color: var(--bg-primary); padding: 0.5rem; border-radius: var(--radius-sm); font-size: 0.85rem;">
            🛡️ <strong>Safe Action:</strong> ${escapeHtml(f.saferAction)}
          </div>
        </div>
      `).join('');
    }

    container.style.display = 'block';
  } catch (err) {
    showToast(err.message || 'Failed to load report', 'error');
  }
});

