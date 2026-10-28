import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { validateInput } from '../../src/engine/input-validation.js';
import { normalizeUrl } from '../../src/engine/url-normalizer.js';
import { analyzeDomain } from '../../src/engine/domain-analysis.js';
import { extractUrlFeatures } from '../../src/engine/url-feature-extractor.js';
import { calculateRiskScore } from '../../src/engine/risk-scoring.js';
import { orchestrateScan } from '../../src/engine/scan-orchestrator.js';

describe('URL Analysis Engine — Unit Tests', () => {
  describe('Input Validation', () => {
    it('accepts valid https URL', () => {
      const res = validateInput('https://example.com/test');
      assert.equal(res.isValid, true);
    });

    it('accepts valid http URL', () => {
      const res = validateInput('http://example.org');
      assert.equal(res.isValid, true);
    });

    it('rejects unsupported javascript: scheme', () => {
      const res = validateInput('javascript:alert(1)');
      assert.equal(res.isValid, false);
      assert.equal(res.code, 'UNSUPPORTED_SCHEME');
    });

    it('rejects unsupported data: scheme', () => {
      const res = validateInput('data:text/html,<script>evil()</script>');
      assert.equal(res.isValid, false);
      assert.equal(res.code, 'UNSUPPORTED_SCHEME');
    });

    it('rejects empty input', () => {
      const res = validateInput('   ');
      assert.equal(res.isValid, false);
      assert.equal(res.code, 'EMPTY_INPUT');
    });

    it('rejects control characters and null bytes', () => {
      const res = validateInput('https://example.com/\x00evil');
      assert.equal(res.isValid, false);
      assert.equal(res.code, 'CONTROL_CHARACTERS');
    });

    it('rejects URLs exceeding max length limit', () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(2100);
      const res = validateInput(longUrl);
      assert.equal(res.isValid, false);
      assert.equal(res.code, 'EXCEEDS_MAX_LENGTH');
    });
  });

  describe('URL Normalizer & Sensitive Data Redaction', () => {
    it('strips HTTP basic auth credentials', () => {
      const parsed = new URL('https://admin:superSecret123@portal.example.com/login');
      const normalized = normalizeUrl(parsed);
      assert.equal(normalized.hadCredentials, true);
      assert.equal(normalized.redactedUrl.includes('superSecret123'), false);
      assert.equal(normalized.redactedUrl, 'https://portal.example.com/login');
    });

    it('redacts sensitive query parameters like token and password', () => {
      const parsed = new URL('https://example.com/verify?token=abc12345xyz&password=mypassword&user=john');
      const normalized = normalizeUrl(parsed);
      assert.equal(normalized.redactedUrl.includes('abc12345xyz'), false);
      assert.equal(normalized.redactedUrl.includes('mypassword'), false);
      assert.equal(normalized.redactedUrl.includes('token=REDACTED'), true);
      assert.equal(normalized.redactedUrl.includes('user=john'), true);
    });

    it('normalizes hostname casing', () => {
      const parsed = new URL('https://ExAmPLE.COM/Path/CasePreserved');
      const normalized = normalizeUrl(parsed);
      assert.equal(normalized.normalizedHostname, 'example.com');
      assert.equal(normalized.pathname, '/Path/CasePreserved');
    });
  });

  describe('Domain Analysis & PSL', () => {
    it('extracts registrable domain accurately with multi-level TLD', () => {
      const res = analyzeDomain('portal.sub.example.co.uk');
      assert.equal(res.registrableDomain, 'example.co.uk');
      assert.equal(res.publicSuffix, 'co.uk');
      assert.equal(res.sld, 'example');
    });

    it('flags IP literal hosts', () => {
      const res = analyzeDomain('192.168.1.100');
      assert.equal(res.isIp, true);
    });

    it('detects Punycode / IDN xn-- prefix', () => {
      const res = analyzeDomain('xn--pple-43d.com');
      assert.equal(res.isPunycode, true);
    });

    it('detects typosquatting visual substitutions (e.g. paypa1 -> paypal)', () => {
      const res = analyzeDomain('paypa1.example.net');
      assert.ok(res.lookalikeMatches.length > 0);
      assert.equal(res.lookalikeMatches[0].targetBrand, 'paypal');
    });

    it('detects brand impersonation in subdomains', () => {
      const res = analyzeDomain('login.paypal.com.account-update.example.org');
      assert.ok(res.brandSubdomainImpersonation.length > 0);
      assert.equal(res.brandSubdomainImpersonation[0].targetBrand, 'paypal');
    });
  });

  describe('Risk Scoring & Clamping', () => {
    it('clamps scores strictly between 0 and 100', () => {
      const findings = [
        { severity: 'critical', scoreWeight: 50 },
        { severity: 'critical', scoreWeight: 60 },
        { severity: 'high', scoreWeight: 30 },
      ];
      const result = calculateRiskScore(findings, null);
      assert.equal(result.riskScore, 100);
      assert.equal(result.riskCategory, 'Critical');
    });

    it('categorizes low observed risk appropriately without claiming 100% safe', () => {
      const findings = [
        { severity: 'low', scoreWeight: 5 },
      ];
      const result = calculateRiskScore(findings, null);
      assert.equal(result.riskScore, 5);
      assert.equal(result.riskCategory, 'Low');
    });

    it('dampens correlated findings when both lookalike and subdomain deception trigger', () => {
      const findings = [
        { ruleId: 'RULE_LOOKALIKE_BRAND', severity: 'critical', scoreWeight: 30 },
        { ruleId: 'RULE_BRAND_SUBDOMAIN_DECEPTION', severity: 'critical', scoreWeight: 30 },
      ];
      const result = calculateRiskScore(findings, null);
      // Lookalike = 30, Brand Subdomain dampened from 30 to 18 = 48
      assert.equal(result.riskScore, 48);
    });
  });

  describe('Orchestrated Scans & End-to-End Engine Behavior', () => {
    it('correctly scores high-risk deceptive phishing URL', async () => {
      const scan = await orchestrateScan('https://chase-security-update.example.net/verify-login?redirect=https://evil.example.org');
      assert.ok(scan.risk_score >= 25);
      assert.ok(scan.findings.length > 0);
      assert.equal(scan.analysis_mode, 'real');
      assert.ok(scan.limitations.length > 0);
    });

    it('reports low observed risk on clean standard reserved domain', async () => {
      const scan = await orchestrateScan('https://example.com/about');
      assert.equal(scan.risk_category, 'Low');
      assert.ok(scan.risk_score <= 24);
      assert.ok(scan.positive_indicators.some(f => f.ruleId === 'RULE_HTTPS_TRANSPORT_ONLY'));
    });
  });
});