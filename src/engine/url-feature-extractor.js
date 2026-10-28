/**
 * URL Feature Extractor
 * Identifies structural anomalies, obfuscations, parameter indicators, and protocol features.
 */

const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'verify',
  'verification',
  'security',
  'account',
  'update',
  'suspended',
  'authenticate',
  'wallet',
  'banking',
  'billing',
  'password',
  'credential',
  'confirm',
  'dispute',
  'unlock',
  'support',
];

const REDIRECT_QUERY_PARAMS = [
  'redirect',
  'redirect_url',
  'redirect_uri',
  'url',
  'next',
  'return_to',
  'dest',
  'destination',
  'target',
  'link',
  'out',
];

export function extractUrlFeatures(normalized) {
  const { rawUrl, normalizedHostname, protocol, port, pathname, search } = normalized;

  // 1. Protocol assessment
  const isHttps = protocol === 'https:';
  const isPlainHttp = protocol === 'http:';

  // 2. Suspicious keywords in path and query
  const fullPathLower = (pathname + search).toLowerCase();
  const matchedKeywords = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (fullPathLower.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  // 3. Open Redirect parameter patterns
  const redirectParamsFound = [];
  const searchParams = new URLSearchParams(search);
  for (const param of REDIRECT_QUERY_PARAMS) {
    if (searchParams.has(param)) {
      const val = searchParams.get(param);
      const pointsToExternal = val.startsWith('http://') || val.startsWith('https://') || val.startsWith('//');
      redirectParamsFound.push({
        param,
        valuePreview: val.length > 50 ? `${val.substring(0, 47)}...` : val,
        pointsToExternal,
      });
    }
  }

  // 4. Excessive or suspicious percent-encoding
  // Count percent-encoded sequences in raw URL
  const percentMatches = rawUrl.match(/%[0-9a-fA-F]{2}/g) || [];
  const percentCount = percentMatches.length;
  const hasEncodedDelimiters = /%(2f|2e|3a|5c|25)/i.test(rawUrl);

  // 5. Length metrics
  const totalLength = rawUrl.length;
  const hostLength = normalizedHostname.length;
  const isExcessiveLength = totalLength > 150;
  const isExcessiveHostLength = hostLength > 50;

  // 6. Non-standard ports (e.g. 8080, 8443, 8888, 2082, 2083)
  const isStandardPort = (isHttps && port === '443') || (isPlainHttp && port === '80');
  const hasCustomPort = !isStandardPort;

  // 7. Excessive dots or hyphens in host
  const dotCount = (normalizedHostname.match(/\./g) || []).length;
  const hyphenCount = (normalizedHostname.match(/-/g) || []).length;

  return {
    isHttps,
    isPlainHttp,
    matchedKeywords,
    redirectParamsFound,
    percentCount,
    hasEncodedDelimiters,
    totalLength,
    hostLength,
    isExcessiveLength,
    isExcessiveHostLength,
    hasCustomPort,
    port,
    dotCount,
    hyphenCount,
  };
}

