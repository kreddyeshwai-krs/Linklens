import { requireAuthPage } from './auth.js';
import { initNavigation } from './navigation.js';
import { apiRequest } from './api.js';
import { escapeHtml, showToast } from './ui-utils.js';

let scenarios = [];
let currentIndex = 0;
let selectedTokens = new Set();

document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuthPage();
  if (!user) return;

  await initNavigation();

  const difficultySelect = document.getElementById('simulator-difficulty-select');
  const submitAnswerBtn = document.getElementById('submit-answer-btn');
  const nextScenarioBtn = document.getElementById('next-scenario-btn');

  difficultySelect.addEventListener('change', () => {
    loadScenarios(difficultySelect.value);
  });

  submitAnswerBtn.addEventListener('click', handleSubmitAnswer);
  nextScenarioBtn.addEventListener('click', handleNextScenario);

  await loadScenarios();
});

async function loadScenarios(difficulty = '') {
  try {
    const query = difficulty ? `?difficulty=${difficulty}` : '';
    const res = await apiRequest(`/learning/scenarios${query}`);
    scenarios = res.scenarios;
    currentIndex = 0;

    if (scenarios.length === 0) {
      document.getElementById('scenario-content').innerHTML = `
        <div style="text-align: center; padding: 3rem; color: var(--text-muted);">
          No educational scenarios currently available for this difficulty level.
        </div>
      `;
      return;
    }

    renderCurrentScenario();
  } catch (err) {
    showToast(err.message || 'Failed to load scenarios', 'error');
  }
}

function tokenizeUrl(urlStr) {
  // Split URL into readable syntactic chunks (protocol, subdomains, domain, path tokens, params)
  const tokens = [];
  try {
    const parsed = new URL(urlStr);
    tokens.push(parsed.protocol + '//');

    const hostParts = parsed.hostname.split('.');
    for (let i = 0; i < hostParts.length; i++) {
      tokens.push(hostParts[i]);
      if (i < hostParts.length - 1) tokens.push('.');
    }

    if (parsed.pathname && parsed.pathname !== '/') {
      const pathParts = parsed.pathname.split('/').filter(Boolean);
      for (const p of pathParts) {
        tokens.push('/' + p);
      }
    }

    if (parsed.search) {
      tokens.push(parsed.search);
    }
  } catch (e) {
    // fallback split by delimiter
    tokens.push(...urlStr.split(/([/:?.&=])/).filter(Boolean));
  }
  return tokens;
}

function renderCurrentScenario() {
  const s = scenarios[currentIndex];
  selectedTokens.clear();

  document.getElementById('scenario-category-badge').textContent = s.category;
  document.getElementById('scenario-difficulty-badge').textContent = s.difficulty.toUpperCase();
  document.getElementById('scenario-title').textContent = s.title;
  document.getElementById('scenario-description').textContent = s.description;
  document.getElementById('scenario-counter').textContent = `Scenario ${currentIndex + 1} of ${scenarios.length}`;

  // Reset feedback
  document.getElementById('scenario-feedback-card').style.display = 'none';
  document.getElementById('submit-answer-btn').style.display = 'inline-flex';
  document.getElementById('submit-answer-btn').disabled = false;
  document.getElementById('next-scenario-btn').style.display = 'none';

  // Render Interactive Clickable URL Tokens
  const tokenBox = document.getElementById('interactive-url-tokens');
  tokenBox.innerHTML = '';

  const tokens = tokenizeUrl(s.sample_url);
  tokens.forEach(tok => {
    const span = document.createElement('span');
    span.className = 'url-token';
    span.textContent = tok;
    span.addEventListener('click', () => {
      if (selectedTokens.has(tok)) {
        selectedTokens.delete(tok);
        span.classList.remove('selected');
      } else {
        selectedTokens.add(tok);
        span.classList.add('selected');
      }
    });
    tokenBox.appendChild(span);
  });
}

async function handleSubmitAnswer() {
  const s = scenarios[currentIndex];
  const submitBtn = document.getElementById('submit-answer-btn');
  submitBtn.disabled = true;

  try {
    const res = await apiRequest(`/learning/scenarios/${s.id}/submit`, {
      method: 'POST',
      body: JSON.stringify({
        selectedIndicators: Array.from(selectedTokens),
      }),
    });

    const attempt = res.attempt;
    const feedback = attempt.feedback;

    const feedbackCard = document.getElementById('scenario-feedback-card');
    feedbackCard.style.display = 'block';

    const feedbackHeader = document.getElementById('feedback-result-header');
    if (attempt.correct) {
      feedbackHeader.innerHTML = `<span style="color: var(--risk-low); font-size: 1.25rem; font-weight: 800;">🎉 Correct! Score: ${attempt.score}%</span>`;
    } else {
      feedbackHeader.innerHTML = `<span style="color: var(--risk-high); font-size: 1.25rem; font-weight: 800;">⚠️ Needs Review. Score: ${attempt.score}%</span>`;
    }

    document.getElementById('feedback-explanation').textContent = feedback.explanation;
    document.getElementById('feedback-safer-action').textContent = feedback.saferAction;

    // Show next button
    submitBtn.style.display = 'none';
    const nextBtn = document.getElementById('next-scenario-btn');
    nextBtn.style.display = 'inline-flex';
  } catch (err) {
    showToast(err.message || 'Failed to submit answer', 'error');
    submitBtn.disabled = false;
  }
}

function handleNextScenario() {
  if (currentIndex < scenarios.length - 1) {
    currentIndex++;
    renderCurrentScenario();
  } else {
    showToast('Congratulations! You completed all scenarios in this set.', 'success');
    currentIndex = 0;
    renderCurrentScenario();
  }
}

