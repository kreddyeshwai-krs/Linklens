import { config } from '../config/index.js';

// Simple in-memory cache for threat intel lookups (10 min TTL)
const intelCache = new Map();
const CACHE_TTL_MS = 600000;

export async function checkThreatIntelligence(redactedUrl, hostname) {
  if (!config.threatIntel.enabled) {
    return {
      checked: false,
      status: 'Not configured',
      provider: 'none',
      isThreat: false,
      threatType: null,
      details: 'External threat intelligence provider is not configured. Analysis relies entirely on explainable structural heuristics.',
      timestamp: new Date().toISOString(),
    };
  }

  const cacheKey = `${config.threatIntel.provider}:${hostname}`;
  const cached = intelCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.data;
  }

  const provider = config.threatIntel.provider.toLowerCase();
  let result;

  try {
    if (provider === 'google' || provider === 'safebrowsing') {
      result = await queryGoogleSafeBrowsing(redactedUrl);
    } else if (provider === 'virustotal') {
      result = await queryVirusTotal(redactedUrl);
    } else {
      result = {
        checked: false,
        status: 'Unsupported provider',
        provider,
        isThreat: false,
        details: `Unknown threat intelligence provider '${provider}'.`,
        timestamp: new Date().toISOString(),
      };
    }
  } catch (error) {
    // CRITICAL: A provider failure MUST produce "Unavailable", NEVER "Clean"!
    result = {
      checked: false,
      status: 'Unavailable',
      provider,
      isThreat: false,
      error: error.message || 'Threat intelligence service failed or timed out',
      details: 'The external threat intelligence service could not be reached. Result is based on heuristic signals only.',
      timestamp: new Date().toISOString(),
    };
  }

  intelCache.set(cacheKey, { timestamp: Date.now(), data: result });
  return result;
}

async function queryGoogleSafeBrowsing(urlToLookup) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3500);

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.threatIntel.apiKey}`;
    const payload = {
      client: {
        clientId: 'link-lens',
        clientVersion: '1.0.0',
      },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: urlToLookup }],
      },
    };

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`Google Safe Browsing returned HTTP ${res.status}`);
    }

    const data = await res.json();
    const hasMatches = Boolean(data.matches && data.matches.length > 0);

    return {
      checked: true,
      status: hasMatches ? 'Known threat reported' : 'No threat reported by provider',
      provider: 'Google Safe Browsing',
      isThreat: hasMatches,
      threatType: hasMatches ? data.matches[0].threatType : null,
      details: hasMatches ? `Listed as ${data.matches[0].threatType} by Google Safe Browsing` : 'No known threats currently recorded in Google Safe Browsing database for this URL.',
      timestamp: new Date().toISOString(),
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function queryVirusTotal(urlToLookup) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3500);

  try {
    const urlId = Buffer.from(urlToLookup).toString('base64url');
    const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

    const res = await fetch(endpoint, {
      headers: { 'x-apikey': config.threatIntel.apiKey },
      signal: controller.signal,
    });

    if (!res.ok) {
      if (res.status === 404) {
        return {
          checked: true,
          status: 'Unknown to provider',
          provider: 'VirusTotal',
          isThreat: false,
          details: 'URL has not been previously analyzed in VirusTotal database.',
          timestamp: new Date().toISOString(),
        };
      }
      throw new Error(`VirusTotal returned HTTP ${res.status}`);
    }

    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const maliciousCount = (stats.malicious || 0) + (stats.suspicious || 0);
    const isThreat = maliciousCount >= 3;

    return {
      checked: true,
      status: isThreat ? 'Known threat reported' : 'No threat reported by provider',
      provider: 'VirusTotal',
      isThreat,
      threatType: isThreat ? `Flagged by ${maliciousCount} security vendors` : null,
      details: `Analyzed by VirusTotal engines: ${stats.malicious || 0} malicious, ${stats.suspicious || 0} suspicious, ${stats.harmless || 0} harmless.`,
      timestamp: new Date().toISOString(),
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

