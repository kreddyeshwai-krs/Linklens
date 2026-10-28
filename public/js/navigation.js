import { getCurrentUser, logout } from './auth.js';
import { initTheme } from './theme.js';
import { escapeHtml } from './ui-utils.js';

export async function initNavigation() {
  // Initialize theme controls
  initTheme();

  // Mobile menu drawer toggle
  const menuToggleBtn = document.getElementById('menu-toggle-btn');
  const sidebar = document.querySelector('.app-sidebar');
  if (menuToggleBtn && sidebar) {
    menuToggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }

  // Highlight active link based on current path
  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href && (currentPath.endsWith(href) || (currentPath === '/' && href === 'index.html'))) {
      link.classList.add('active');
    }
  });

  // Display user badge in header if authenticated
  const user = await getCurrentUser();
  const userContainer = document.getElementById('header-user-badge');
  const adminNavItem = document.getElementById('nav-admin-link');

  if (user && userContainer) {
    userContainer.innerHTML = `
      <div class="user-profile-badge">
        <div class="user-avatar">${escapeHtml(user.displayName.charAt(0).toUpperCase())}</div>
        <span>${escapeHtml(user.displayName)}</span>
        <button id="logout-btn" class="btn btn-sm btn-outline" style="padding: 0.2rem 0.5rem; margin-left: 0.5rem;" title="Sign out">Sign out</button>
      </div>
    `;

    document.getElementById('logout-btn')?.addEventListener('click', (e) => {
      e.preventDefault();
      logout();
    });

    if (adminNavItem && user.role === 'admin') {
      adminNavItem.style.display = 'flex';
    }
  }
}

