import { requireAuthPage } from './auth.js';
import { initNavigation } from './navigation.js';
import { apiRequest } from './api.js';
import { escapeHtml, renderRiskBadge, formatDate } from './ui-utils.js';

document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuthPage();
  if (!user) return;

  await initNavigation();

  const welcomeName = document.getElementById('welcome-user-name');
  if (welcomeName) welcomeName.textContent = user.displayName;

  // Load User Progress & Dashboard metrics
  try {
    const progressData = await apiRequest('/progress');
    const p = progressData.progress;

    document.getElementById('stat-total-scans').textContent = p.totalScans;
    document.getElementById('stat-completed-scenarios').textContent = `${p.completedScenarios} / ${p.totalScenarios}`;
    document.getElementById('stat-passed-quizzes').textContent = `${p.passedQuizzes} / ${p.totalQuizzes}`;
    document.getElementById('learning-progress-bar').style.width = `${p.learningProgressPct}%`;
    document.getElementById('learning-progress-pct').textContent = `${p.learningProgressPct}% Completed`;

    // Render Recent Scans
    const recentScansList = document.getElementById('recent-scans-table-body');
    if (recentScansList) {
      if (p.recentScans.length === 0) {
        recentScansList.innerHTML = `
          <tr>
            <td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-muted);">
              No scans performed yet. Enter a URL in the Scanner to initiate your first analysis.
            </td>
          </tr>
        `;
      } else {
        recentScansList.innerHTML = p.recentScans.map(s => `
          <tr>
            <td><strong class="mono-font">${escapeHtml(s.normalized_hostname)}</strong></td>
            <td>${renderRiskBadge(s.risk_category, s.risk_score)}</td>
            <td>${formatDate(s.analyzed_at)}</td>
            <td><a href="/scan-details.html?id=${s.id}" class="btn btn-sm btn-outline">View Details</a></td>
          </tr>
        `).join('');
      }
    }

    // Quick Scan Form in Dashboard
    const quickScanForm = document.getElementById('dashboard-quick-scan-form');
    if (quickScanForm) {
      quickScanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const urlInput = document.getElementById('quick-scan-input').value.trim();
        if (urlInput) {
          window.location.href = `/scanner.html?url=${encodeURIComponent(urlInput)}`;
        }
      });
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load dashboard metrics:', err);
  }
});

