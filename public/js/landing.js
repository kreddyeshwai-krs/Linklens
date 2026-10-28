import { initTheme } from './theme.js';
import { getCurrentUser } from './auth.js';

document.addEventListener('DOMContentLoaded', async () => {
  initTheme();

  // Check auth to toggle CTA button text
  const user = await getCurrentUser();
  const ctaBtn = document.getElementById('primary-cta-btn');
  if (user && ctaBtn) {
    ctaBtn.textContent = 'Go to Dashboard';
    ctaBtn.href = '/dashboard.html';
  }
});

