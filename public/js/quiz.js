import { requireAuthPage } from './auth.js';
import { initNavigation } from './navigation.js';
import { apiRequest } from './api.js';
import { escapeHtml, showToast } from './ui-utils.js';

let activeQuiz = null;
let currentQuestionIndex = 0;
let userAnswers = {};
let timerInterval = null;
let secondsRemaining = 0;

document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuthPage();
  if (!user) return;

  await initNavigation();

  const quizSelect = document.getElementById('quiz-selector');
  quizSelect.addEventListener('change', () => {
    if (quizSelect.value) {
      loadQuiz(quizSelect.value);
    }
  });

  document.getElementById('prev-question-btn').addEventListener('click', () => {
    if (currentQuestionIndex > 0) {
      currentQuestionIndex--;
      renderQuestion();
    }
  });

  document.getElementById('next-question-btn').addEventListener('click', () => {
    if (currentQuestionIndex < activeQuiz.questions.length - 1) {
      currentQuestionIndex++;
      renderQuestion();
    }
  });

  document.getElementById('submit-quiz-btn').addEventListener('click', submitQuiz);
  document.getElementById('retry-quiz-btn').addEventListener('click', () => {
    userAnswers = {};
    currentQuestionIndex = 0;
    document.getElementById('quiz-results-card').style.display = 'none';
    document.getElementById('quiz-questions-card').style.display = 'block';
    renderQuestion();
  });

  await loadQuizList();
});

async function loadQuizList() {
  try {
    const res = await apiRequest('/learning/quizzes');
    const select = document.getElementById('quiz-selector');
    select.innerHTML = '<option value="">-- Choose an Assessment Quiz --</option>' +
      res.quizzes.map(q => `<option value="${q.id}">${escapeHtml(q.title)} [${escapeHtml(q.difficulty)}]</option>`).join('');

    if (res.quizzes.length > 0) {
      select.value = res.quizzes[0].id;
      await loadQuiz(res.quizzes[0].id);
    }
  } catch (err) {
    showToast(err.message || 'Failed to load quizzes', 'error');
  }
}

async function loadQuiz(quizId) {
  try {
    const res = await apiRequest(`/learning/quizzes/${quizId}`);
    activeQuiz = res.quiz;
    userAnswers = {};
    currentQuestionIndex = 0;

    document.getElementById('quiz-title').textContent = activeQuiz.title;
    document.getElementById('quiz-desc').textContent = activeQuiz.description;
    document.getElementById('quiz-difficulty-tag').textContent = activeQuiz.difficulty.toUpperCase();

    document.getElementById('quiz-questions-card').style.display = 'block';
    document.getElementById('quiz-results-card').style.display = 'none';

    renderQuestion();
  } catch (err) {
    showToast(err.message || 'Failed to load quiz details', 'error');
  }
}

function renderQuestion() {
  const q = activeQuiz.questions[currentQuestionIndex];
  const total = activeQuiz.questions.length;

  document.getElementById('question-counter').textContent = `Question ${currentQuestionIndex + 1} of ${total} (${q.points} pts)`;
  document.getElementById('question-type-label').textContent = q.question_type === 'multiple_choice' ? 'Select all that apply' : 'Single Choice';
  document.getElementById('question-text').textContent = q.question_text;

  const optionsContainer = document.getElementById('quiz-options-container');
  optionsContainer.innerHTML = '';

  const isMulti = q.question_type === 'multiple_choice';
  const currentSelection = userAnswers[q.id] || (isMulti ? [] : null);

  q.public_options.forEach(opt => {
    const isSelected = isMulti ? currentSelection.includes(opt.id) : currentSelection === opt.id;
    const div = document.createElement('div');
    div.className = `quiz-option ${isSelected ? 'selected' : ''}`;
    div.innerHTML = `
      <div style="font-size: 1.1rem;">${isSelected ? '☑️' : '◻️'}</div>
      <div style="flex: 1;">${escapeHtml(opt.text)}</div>
    `;

    div.addEventListener('click', () => {
      if (isMulti) {
        let arr = userAnswers[q.id] || [];
        if (arr.includes(opt.id)) {
          arr = arr.filter(id => id !== opt.id);
        } else {
          arr = [...arr, opt.id];
        }
        userAnswers[q.id] = arr;
      } else {
        userAnswers[q.id] = opt.id;
      }
      renderQuestion();
    });

    optionsContainer.appendChild(div);
  });

  // Buttons navigation
  document.getElementById('prev-question-btn').disabled = currentQuestionIndex === 0;
  const nextBtn = document.getElementById('next-question-btn');
  const submitBtn = document.getElementById('submit-quiz-btn');

  if (currentQuestionIndex === total - 1) {
    nextBtn.style.display = 'none';
    submitBtn.style.display = 'inline-flex';
  } else {
    nextBtn.style.display = 'inline-flex';
    submitBtn.style.display = 'none';
  }
}

async function submitQuiz() {
  const submitBtn = document.getElementById('submit-quiz-btn');
  submitBtn.disabled = true;

  try {
    const res = await apiRequest(`/learning/quizzes/${activeQuiz.id}/submit`, {
      method: 'POST',
      body: JSON.stringify({ answers: userAnswers }),
    });

    const attempt = res.attempt;

    // Show Results Card
    document.getElementById('quiz-questions-card').style.display = 'none';
    const resultsCard = document.getElementById('quiz-results-card');
    resultsCard.style.display = 'block';

    const scoreElem = document.getElementById('final-quiz-score');
    scoreElem.textContent = `${attempt.score}%`;
    scoreElem.style.color = attempt.score >= 70 ? 'var(--risk-low)' : 'var(--risk-high)';

    document.getElementById('final-quiz-points').textContent = `Earned ${attempt.total_points} total points.`;

    const reviewList = document.getElementById('quiz-review-list');
    reviewList.innerHTML = attempt.answers.map(ans => `
      <div class="card" style="margin-bottom: 1rem; border-left: 4px solid ${ans.isCorrect ? 'var(--risk-low)' : 'var(--risk-critical)'};">
        <div class="card-body">
          <p><strong>${escapeHtml(ans.questionText)}</strong></p>
          <div style="font-size: 0.9rem; margin: 0.5rem 0;">
            ${ans.isCorrect ? '✅ <span style="color: var(--risk-low);">Correct</span>' : '❌ <span style="color: var(--risk-critical);">Incorrect</span>'} (+${ans.points} pts)
          </div>
          <p style="font-size: 0.85rem; color: var(--text-secondary);"><strong style="color: var(--text-primary);">Explanation:</strong> ${escapeHtml(ans.explanation)}</p>
        </div>
      </div>
    `).join('');

    showToast('Quiz evaluated and saved', 'success');
  } catch (err) {
    showToast(err.message || 'Submission failed', 'error');
    submitBtn.disabled = false;
  }
}

