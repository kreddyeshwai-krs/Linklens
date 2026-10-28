/**
 * Theme Manager
 * Supports 'dark', 'light', and 'system' preferences with persistent localStorage.
 */

const THEME_STORAGE_KEY = 'linklens_theme_preference';

export function getPreferredTheme() {
  const stored = localStorage.getItem(THEME_STORAGE_KEY);
  if (stored === 'dark' || stored === 'light') {
    return stored;
  }
  // Default to system preference
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    return 'light';
  }
  return 'dark';
}

export function applyTheme(theme) {
  const activeTheme = theme === 'system' ? getPreferredTheme() : theme;
  document.documentElement.setAttribute('data-theme', activeTheme);
  localStorage.setItem(THEME_STORAGE_KEY, theme);

  // Update theme toggle button icon if present
  const toggleBtn = document.getElementById('theme-toggle-btn');
  if (toggleBtn) {
    toggleBtn.innerHTML = activeTheme === 'light' ? '🌙' : '☀️';
    toggleBtn.setAttribute('title', `Switch to ${activeTheme === 'light' ? 'Dark' : 'Light'} Mode`);
    toggleBtn.setAttribute('aria-label', `Switch to ${activeTheme === 'light' ? 'Dark' : 'Light'} Mode`);
  }
}

export function initTheme() {
  const current = getPreferredTheme();
  applyTheme(current);

  const toggleBtn = document.getElementById('theme-toggle-btn');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const currentActive = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = currentActive === 'dark' ? 'light' : 'dark';
      applyTheme(next);
    });
  }

  // React to system preference changes if user hasn't explicitly locked a preference
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
      const stored = localStorage.getItem(THEME_STORAGE_KEY);
      if (!stored || stored === 'system') {
        applyTheme(e.matches ? 'light' : 'dark');
      }
    });
  }
}

