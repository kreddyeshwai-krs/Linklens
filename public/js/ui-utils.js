export function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function showToast(message, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', 'alert');
  toast.innerHTML = `
    <span>${type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️'}</span>
    <div>${escapeHtml(message)}</div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.25s ease-out';
    setTimeout(() => toast.remove(), 250);
  }, duration);
}

export function showConfirmModal({ title, message, confirmText = 'Confirm', confirmClass = 'btn-danger', onConfirm }) {
  let modalBackdrop = document.getElementById('app-confirm-modal');
  if (!modalBackdrop) {
    modalBackdrop = document.createElement('div');
    modalBackdrop.id = 'app-confirm-modal';
    modalBackdrop.className = 'modal-backdrop';
    document.body.appendChild(modalBackdrop);
  }

  modalBackdrop.innerHTML = `
    <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div class="card-header">
        <h3 id="modal-title" class="card-title">⚠️ ${escapeHtml(title)}</h3>
      </div>
      <div class="card-body">
        <p>${escapeHtml(message)}</p>
      </div>
      <div class="card-footer">
        <button id="modal-cancel-btn" class="btn btn-secondary">Cancel</button>
        <button id="modal-action-btn" class="btn ${confirmClass}">${escapeHtml(confirmText)}</button>
      </div>
    </div>
  `;

  modalBackdrop.classList.add('open');

  const close = () => {
    modalBackdrop.classList.remove('open');
  };

  document.getElementById('modal-cancel-btn').onclick = close;
  modalBackdrop.onclick = (e) => {
    if (e.target === modalBackdrop) close();
  };

  document.getElementById('modal-action-btn').onclick = async () => {
    close();
    if (onConfirm) await onConfirm();
  };
}

export function renderRiskBadge(category, score) {
  const cat = (category || 'low').toLowerCase();
  const label = score !== undefined ? `${escapeHtml(category)} (${score})` : escapeHtml(category);
  return `<span class="badge badge-${cat}">${label}</span>`;
}

export function renderRiskDial(score, category) {
  const cat = (category || 'low').toLowerCase();
  return `
    <div class="risk-dial-container">
      <div class="risk-dial ${cat}">
        <span class="dial-score">${score}</span>
        <span class="dial-max">/ 100</span>
      </div>
      <div style="margin-top: 1rem; text-align: center;">
        ${renderRiskBadge(category)}
      </div>
    </div>
  `;
}

export function formatDate(isoString) {
  if (!isoString) return 'N/A';
  try {
    const d = new Date(isoString);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch (e) {
    return isoString;
  }
}

