/**
 * Risk Scoring Engine
 * Computes deterministic, explainable risk score (0-100)
 * with correlated-finding dampening and evidence quality classification.
 */

export const RULESET_VERSION = '1.2.0';

export function calculateRiskScore(findings, threatInfo) {
  let rawScore = 0;
  const categoriesPresent = new Set();

  // Correlated finding rules:
  // If lookalike domain AND brand subdomain deception are both present, dampen the second one
  let hasLookalike = false;
  let hasBrandSubdomain = false;

  for (const finding of findings) {
    let weight = finding.scoreWeight || 0;

    if (finding.ruleId === 'RULE_LOOKALIKE_BRAND') {
      hasLookalike = true;
    }
    if (finding.ruleId === 'RULE_BRAND_SUBDOMAIN_DECEPTION') {
      hasBrandSubdomain = true;
      if (hasLookalike) {
        // Dampen correlation: reduce weight by 40% to avoid double penalizing the same underlying brand deception
        weight = Math.round(weight * 0.6);
      }
    }

    rawScore += weight;
    categoriesPresent.add(finding.severity);
  }

  // Clamp final score strictly between 0 and 100
  const riskScore = Math.min(100, Math.max(0, rawScore));

  // Determine Risk Category
  let riskCategory;
  if (riskScore <= 24) {
    riskCategory = 'Low';
  } else if (riskScore <= 49) {
    riskCategory = 'Moderate';
  } else if (riskScore <= 74) {
    riskCategory = 'High';
  } else {
    riskCategory = 'Critical';
  }

  // Determine Confidence / Evidence Quality
  let confidenceLevel = 'Moderate';
  if (threatInfo && threatInfo.isThreat) {
    confidenceLevel = 'Verified';
  } else if (findings.some(f => f.severity === 'critical' || f.severity === 'high')) {
    confidenceLevel = 'High';
  } else if (findings.length === 1 && findings[0].ruleId === 'RULE_HTTPS_TRANSPORT_ONLY') {
    confidenceLevel = 'Low';
  }

  return {
    riskScore,
    riskCategory,
    confidenceLevel,
    rulesetVersion: RULESET_VERSION,
    rawScore,
  };
}

