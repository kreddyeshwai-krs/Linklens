import { requireAdminPage } from './auth.js';
import { initNavigation } from './navigation.js';
import { apiRequest } from './api.js';
import { escapeHtml, renderRiskBadge, formatDate, showToast } from './ui-utils.js';

document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAdminPage();
  if (!user) return;

  await initNavigation();

  await loadAdminOverview();
  await loadAdminScans();
  await loadContentManagement();
  await loadAuditLogs();
});

async function loadAdminOverview() {
  try {
    const res = await apiRequest('/admin/overview');
    const { totalUsers, totalScans, totalAttempts, riskStats } = res.overview;

    document.getElementById('admin-total-users').textContent = totalUsers;
    document.getElementById('admin-total-scans').textContent = totalScans;
    document.getElementById('admin-total-attempts').textContent = totalAttempts;

    document.getElementById('stat-risk-critical').textContent = riskStats.Critical || 0;
    document.getElementById('stat-risk-high').textContent = riskStats.High || 0;
    document.getElementById('stat-risk-moderate').textContent = riskStats.Moderate || 0;
    document.getElementById('stat-risk-low').textContent = riskStats.Low || 0;
  } catch (err) {
    showToast(err.message || 'Failed to load admin overview', 'error');
  }
}

async function loadAdminScans() {
  const tbody = document.getElementById('admin-scans-table-body');
  try {
    const res = await apiRequest('/admin/scans?limit=15');
    if (res.scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem;">No system scans recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = res.scans.map(s => `
      <tr>
        <td><strong>${escapeHtml(s.profiles?.display_name || 'Anonymous')}</strong></td>
        <td><span class="mono-font">${escapeHtml(s.normalized_hostname)}</span></td>
        <td>${renderRiskBadge(s.risk_category, s.risk_score)}</td>
        <td>${formatDate(s.analyzed_at)}</td>
        <td><a href="/scan-details.html?id=${s.id}" class="btn btn-sm btn-outline">Inspect</a></td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" style="color: var(--risk-critical);">${escapeHtml(err.message)}</td></tr>`;
  }
}

async function loadContentManagement() {
  const scenariosList = document.getElementById('admin-scenarios-list');
  try {
    // Fetch all scenarios (including disabled ones)
    const res = await apiRequest('/learning/scenarios');
    scenariosList.innerHTML = res.scenarios.map(s => `
      <div class="card" style="margin-bottom: 0.75rem; padding: 1rem; display: flex; align-items: center; justify-content: space-between;">
        <div>
          <strong>${escapeHtml(s.title)}</strong>
          <span style="font-size: 0.8rem; color: var(--text-muted); margin-left: 0.5rem;">[${escapeHtml(s.difficulty)}]</span>
        </div>
        <div>
          <button class="btn btn-sm ${s.enabled ? 'btn-outline' : 'btn-primary'} toggle-scenario-btn" data-id="${s.id}" data-enabled="${s.enabled}">
            ${s.enabled ? 'Deactivate' : 'Activate'}
          </button>
        </div>
      </div>
    `).join('');

    document.querySelectorAll('.toggle-scenario-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.target.getAttribute('data-id');
        const currentlyEnabled = e.target.getAttribute('data-enabled') === 'true';
        try {
          await apiRequest(`/admin/scenarios/${id}`, {
            method: 'PATCH',
            body: JSON.stringify({ enabled: !currentlyEnabled }),
          });
          showToast(`Scenario ${!currentlyEnabled ? 'activated' : 'deactivated'}`, 'success');
          await loadContentManagement();
        } catch (err) {
          showToast(err.message || 'Toggle failed', 'error');
        }
      });
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load scenarios:', err);
  }
}

async function loadAuditLogs() {
  const tbody = document.getElementById('admin-audit-table-body');
  try {
    const res = await apiRequest('/admin/audit-logs?limit=15');
    if (res.logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem;">No audit logs recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = res.logs.map(l => `
      <tr>
        <td><strong>${escapeHtml(l.action)}</strong></td>
        <td>${escapeHtml(l.target_type)} (${escapeHtml(l.target_id)})</td>
        <td>${formatDate(l.created_at)}</td>
        <td><code class="mono-font" style="font-size: 0.75rem;">${escapeHtml(JSON.stringify(l.metadata))}</code></td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" style="color: var(--risk-critical);">${escapeHtml(err.message)}</td></tr>`;
  }
}

