import { requireAuthPage } from './auth.js';
import { initNavigation } from './navigation.js';
import { apiRequest } from './api.js';
import { escapeHtml, renderRiskBadge, formatDate, showConfirmModal, showToast } from './ui-utils.js';

let currentPage = 1;
const limit = 10;
let currentSearch = '';
let currentCategory = '';

document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuthPage();
  if (!user) return;

  await initNavigation();

  const searchInput = document.getElementById('history-search-input');
  const categoryFilter = document.getElementById('history-category-filter');
  const clearAllBtn = document.getElementById('clear-history-btn');
  const prevPageBtn = document.getElementById('prev-page-btn');
  const nextPageBtn = document.getElementById('next-page-btn');

  searchInput.addEventListener('input', debounce((e) => {
    currentSearch = e.target.value.trim();
    currentPage = 1;
    loadHistory();
  }, 300));

  categoryFilter.addEventListener('change', (e) => {
    currentCategory = e.target.value;
    currentPage = 1;
    loadHistory();
  });

  clearAllBtn.addEventListener('click', () => {
    showConfirmModal({
      title: 'Clear Entire Scan History',
      message: 'Are you sure you want to permanently clear all your saved URL analysis records? This cannot be undone.',
      confirmText: 'Clear All History',
      onConfirm: async () => {
        try {
          await apiRequest('/scans', { method: 'DELETE' });
          showToast('Scan history cleared', 'success');
          currentPage = 1;
          await loadHistory();
        } catch (err) {
          showToast(err.message || 'Failed to clear history', 'error');
        }
      },
    });
  });

  prevPageBtn.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      loadHistory();
    }
  });

  nextPageBtn.addEventListener('click', () => {
    currentPage++;
    loadHistory();
  });

  await loadHistory();
});

async function loadHistory() {
  const tbody = document.getElementById('history-table-body');
  const pageIndicator = document.getElementById('page-indicator');
  const prevBtn = document.getElementById('prev-page-btn');
  const nextBtn = document.getElementById('next-page-btn');

  tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem;">Loading scan records...</td></tr>';

  try {
    const query = new URLSearchParams({
      page: currentPage,
      limit,
      search: currentSearch,
      riskCategory: currentCategory,
    });

    const data = await apiRequest(`/scans?${query.toString()}`);
    const { scans, total, totalPages } = data;

    pageIndicator.textContent = `Page ${currentPage} of ${totalPages || 1} (${total} total)`;
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = currentPage >= totalPages;

    if (scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align: center; padding: 3rem; color: var(--text-muted);">
            No scan records found matching the active filters.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = scans.map(s => `
      <tr>
        <td><strong class="mono-font">${escapeHtml(s.normalized_hostname)}</strong></td>
        <td><span style="font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(s.submitted_url_redacted)}</span></td>
        <td>${renderRiskBadge(s.risk_category, s.risk_score)}</td>
        <td>${formatDate(s.analyzed_at)}</td>
        <td style="white-space: nowrap;">
          <a href="/scan-details.html?id=${s.id}" class="btn btn-sm btn-outline" style="margin-right: 0.5rem;">Report</a>
          <button class="btn btn-sm btn-outline delete-single-scan" data-id="${s.id}" style="color: var(--risk-critical); border-color: var(--border-subtle);">Delete</button>
        </td>
      </tr>
    `).join('');

    // Attach single delete listeners
    document.querySelectorAll('.delete-single-scan').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.target.getAttribute('data-id');
        showConfirmModal({
          title: 'Delete Scan',
          message: 'Delete this scan from history?',
          confirmText: 'Delete',
          onConfirm: async () => {
            try {
              await apiRequest(`/scans/${id}`, { method: 'DELETE' });
              showToast('Scan deleted', 'success');
              await loadHistory();
            } catch (err) {
              showToast(err.message || 'Deletion failed', 'error');
            }
          },
        });
      });
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--risk-critical); padding: 2rem;">${escapeHtml(err.message)}</td></tr>`;
  }
}

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

