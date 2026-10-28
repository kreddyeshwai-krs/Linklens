import { requireAuthPage } from './auth.js';
import { initNavigation } from './navigation.js';
import { apiRequest } from './api.js';
import { escapeHtml, renderRiskDial, renderRiskBadge, showToast } from './ui-utils.js';

document.addEventListener('DOMContentLoaded', async () => {
  const user = await requireAuthPage();
  if (!user) return;

  await initNavigation();

  const scanForm = document.getElementById('url-scan-form');
  const urlInput = document.getElementById('scan-url-input');
  const submitBtn = document.getElementById('scan-submit-btn');
  const resultsContainer = document.getElementById('scan-results-container');
  const loadingIndicator = document.getElementById('scan-loading-indicator');

  // Check URL query param
  const urlParam = new URLSearchParams(window.location.search).get('url');
  if (urlParam) {
    urlInput.value = urlParam;
    executeScan(urlParam);
  }

  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const rawUrl = urlInput.value.trim();
    if (!rawUrl) {
      showToast('Please enter a URL to inspect', 'error');
      return;
    }
    await executeScan(rawUrl);
  });

  async function executeScan(targetUrl) {
    submitBtn.disabled = true;
    loadingIndicator.style.display = 'block';
    resultsContainer.style.display = 'none';

    try {
      const res = await apiRequest('/scans', {
        method: 'POST',
        body: JSON.stringify({ url: targetUrl, analysisMode: 'real' }),
      });

      renderScanResults(res.scan);
      showToast('URL analysis completed', 'success');
    } catch (err) {
      showToast(err.message || 'Analysis failed', 'error');
    } finally {
      submitBtn.disabled = false;
      loadingIndicator.style.display = 'none';
    }
  }

  function renderScanResults(scan) {
    resultsContainer.style.display = 'block';

    // Risk Dial & Metadata
    document.getElementById('result-risk-dial').innerHTML = renderRiskDial(scan.risk_score, scan.risk_category);
    document.getElementById('result-hostname').textContent = scan.normalized_hostname;
    document.getElementById('result-domain').textContent = scan.registrable_domain || 'N/A';
    document.getElementById('result-confidence').textContent = scan.confidence_level;
    document.getElementById('result-ruleset').textContent = `v${scan.ruleset_version}`;
    document.getElementById('result-redacted-url').textContent = scan.submitted_url_redacted;

    // View Details / Print Report Link
    const detailsLink = document.getElementById('view-full-report-btn');
    if (detailsLink) {
      detailsLink.href = `/scan-details.html?id=${scan.id}`;
    }

    // Threat Intel Status
    const intel = scan.provider_results || {};
    const intelStatusElem = document.getElementById('result-intel-status');
    intelStatusElem.textContent = `${intel.provider || 'Local Heuristics'}: ${intel.status || 'Not checked'}`;

    // Risk Findings Breakdown
    const findingsList = document.getElementById('result-findings-list');
    if (scan.findings.length === 0) {
      findingsList.innerHTML = `
        <div class="card" style="padding: 1.5rem; text-align: center; border-left: 4px solid var(--risk-low);">
          <h4 style="color: var(--risk-low); margin-bottom: 0.5rem;">✅ No Major Red Flags Detected</h4>
          <p>The structural inspection did not uncover prominent deceptive patterns or known threats. Always confirm sender authenticity before sharing credentials.</p>
        </div>
      `;
    } else {
      findingsList.innerHTML = scan.findings.map(f => `
        <div class="finding-item ${escapeHtml(f.severity)}">
          <div class="finding-header">
            <span class="finding-title">${escapeHtml(f.title)}</span>
            <span class="badge badge-${escapeHtml(f.severity)}">${escapeHtml(f.severity)} (+${f.scoreWeight} pts)</span>
          </div>
          <div class="finding-evidence">
            <strong>Evidence:</strong> ${escapeHtml(f.evidence)}
          </div>
          <p class="finding-meta">${escapeHtml(f.explanation)}</p>
          <p style="font-size: 0.85rem; color: var(--text-muted);"><strong style="color: var(--text-secondary);">Why it matters:</strong> ${escapeHtml(f.whyItMatters)}</p>
          <div style="background-color: var(--bg-primary); padding: 0.6rem; border-radius: var(--radius-sm); font-size: 0.85rem;">
            🛡️ <strong style="color: var(--accent-cyan);">Recommended Safe Action:</strong> ${escapeHtml(f.saferAction)}
          </div>
        </div>
      `).join('');
    }

    // Mitigating / Positive Indicators
    const positiveList = document.getElementById('result-positive-list');
    if (scan.positive_indicators && scan.positive_indicators.length > 0) {
      positiveList.innerHTML = scan.positive_indicators.map(f => `
        <div class="finding-item info">
          <div class="finding-header">
            <span class="finding-title">ℹ️ ${escapeHtml(f.title)}</span>
            <span class="badge badge-neutral">Educational Notice</span>
          </div>
          <p class="finding-meta">${escapeHtml(f.explanation)}</p>
        </div>
      `).join('');
    } else {
      positiveList.innerHTML = '<p style="color: var(--text-muted); font-size: 0.9rem;">None observed.</p>';
    }

    // Next steps
    const nextStepsList = document.getElementById('result-next-steps');
    if (nextStepsList && scan.recommended_next_steps) {
      nextStepsList.innerHTML = scan.recommended_next_steps.map(step => `<li>${escapeHtml(step)}</li>`).join('');
    }
  }
});

