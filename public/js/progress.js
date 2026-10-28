import { requireAuthPage } from './auth.js';
import { initNavigation } from './navigation.js';
import { apiRequest } from './api.js';
import { escapeHtml, formatDate } from './ui-utils.js';

document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuthPage();
  if (!user) return;

  await initNavigation();

  try {
    const res = await apiRequest('/progress');
    const p = res.progress;

    document.getElementById('metric-total-scans').textContent = p.totalScans;
    document.getElementById('metric-scenarios').textContent = `${p.completedScenarios} / ${p.totalScenarios}`;
    document.getElementById('metric-quizzes').textContent = `${p.passedQuizzes} / ${p.totalQuizzes}`;

    document.getElementById('progress-bar-learning').style.width = `${p.learningProgressPct}%`;
    document.getElementById('progress-pct-learning').textContent = `${p.learningProgressPct}%`;

    document.getElementById('progress-bar-quizzes').style.width = `${p.quizProgressPct}%`;
    document.getElementById('progress-pct-quizzes').textContent = `${p.quizProgressPct}%`;

    // Render Badges
    const badgeGrid = document.getElementById('badges-grid-container');
    if (p.badges.length === 0) {
      badgeGrid.innerHTML = `
        <div style="grid-column: 1 / -1; text-align: center; padding: 2rem; color: var(--text-muted);">
          Complete your first URL scan or educational scenario to earn certification badges!
        </div>
      `;
    } else {
      badgeGrid.innerHTML = p.badges.map(b => `
        <div class="badge-item">
          <div class="badge-icon">${b.icon}</div>
          <strong style="color: var(--text-primary);">${escapeHtml(b.title)}</strong>
          <span style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(b.desc)}</span>
        </div>
      `).join('');
    }

    // Load Quiz Attempt History
    const attemptsRes = await apiRequest('/learning/attempts');
    const attemptsTable = document.getElementById('quiz-attempts-table-body');
    if (attemptsTable) {
      if (attemptsRes.quizAttempts.length === 0) {
        attemptsTable.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-muted);">No quiz attempts recorded yet.</td></tr>';
      } else {
        attemptsTable.innerHTML = attemptsRes.quizAttempts.map(a => `
          <tr>
            <td><strong>${escapeHtml(a.quizzes?.title || 'Cybersecurity Assessment')}</strong></td>
            <td><span class="badge ${a.score >= 70 ? 'badge-low' : 'badge-high'}">${a.score}%</span></td>
            <td>${a.total_points} pts</td>
            <td>${formatDate(a.completed_at)}</td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load progress:', err);
  }
});

