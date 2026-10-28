import { validateInput } from './input-validation.js';
import { normalizeUrl } from './url-normalizer.js';
import { analyzeDomain } from './domain-analysis.js';
import { extractUrlFeatures } from './url-feature-extractor.js';
import { analyzeRedirects } from './redirect-analysis.js';
import { checkThreatIntelligence } from './threat-intelligence.js';
import { generateFindings } from './findings-explainer.js';
import { calculateRiskScore } from './risk-scoring.js';

export async function orchestrateScan(rawUrlInput) {
  // Step 1: Validate input
  const validation = validateInput(rawUrlInput);
  if (!validation.isValid) {
    const error = new Error(validation.error);
    error.code = validation.code;
    error.statusCode = 400;
    throw error;
  }

  // Step 2: Normalize safely and redact credentials/secrets
  const normalized = normalizeUrl(validation.parsed);

  // Step 3: Domain and lookalike analysis using PSL
  const domainInfo = analyzeDomain(normalized.normalizedHostname);

  // Step 4: URL feature extraction
  const features = extractUrlFeatures(normalized);

  // Step 5: Safe redirect and shortener analysis
  const redirectInfo = analyzeRedirects(domainInfo);

  // Step 6: Optional threat intelligence lookup
  const threatInfo = await checkThreatIntelligence(normalized.redactedUrl, normalized.normalizedHostname);

  // Step 7: Formulate explainable findings
  const allFindings = generateFindings({
    domainInfo,
    features,
    redirectInfo,
    threatInfo,
  });

  // Separate positive / educational mitigating findings from risk findings
  const positiveIndicators = allFindings.filter(f => f.severity === 'info');
  const riskFindings = allFindings.filter(f => f.severity !== 'info');

  // Step 8: Calculate risk score and confidence
  const scoring = calculateRiskScore(riskFindings, threatInfo);

  // Recommended next steps based on risk
  const recommendedNextSteps = [];
  if (scoring.riskCategory === 'Critical' || scoring.riskCategory === 'High') {
    recommendedNextSteps.push('Do NOT open this URL or authenticate your account credentials.');
    recommendedNextSteps.push('Report this message or link to your organization security team or anti-phishing provider.');
    recommendedNextSteps.push('If you already visited the link or entered credentials, immediately change your password and revoke active sessions.');
  } else if (scoring.riskCategory === 'Moderate') {
    recommendedNextSteps.push('Proceed with caution: verify the sender or navigate directly to the verified official portal.');
    recommendedNextSteps.push('Inspect destination redirection parameters before authenticating.');
  } else {
    recommendedNextSteps.push('No major red flags detected in URL structure. Exercise standard browsing caution.');
    recommendedNextSteps.push('Always confirm the content matches expected services before entering sensitive credentials.');
  }

  const limitations = [
    'Assessment is based on URL structure, domain registration metadata, and configured intelligence feeds.',
    'Page contents, client-side scripts, and active payloads were not rendered or executed on this server.',
    'A low score represents low observed heuristic risk, not an absolute guarantee of safety.',
  ];

  return {
    submitted_url_redacted: normalized.redactedUrl,
    normalized_hostname: normalized.normalizedHostname,
    registrable_domain: domainInfo.registrableDomain,
    public_suffix: domainInfo.publicSuffix,
    risk_score: scoring.riskScore,
    risk_category: scoring.riskCategory,
    confidence_level: scoring.confidenceLevel,
    analysis_mode: 'real',
    ruleset_version: scoring.rulesetVersion,
    findings: riskFindings,
    positive_indicators: positiveIndicators,
    provider_results: threatInfo,
    limitations,
    recommended_next_steps: recommendedNextSteps,
    analyzed_at: new Date().toISOString(),
  };
}

