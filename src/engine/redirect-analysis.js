/**
 * Safe Redirect and Shortener Analysis
 * Detects URL shortening services and masked redirect structures.
 * By design, does NOT make unconstrained remote HTTP requests to avoid SSRF hazards.
 */

const KNOWN_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'adf.ly',
  'bitly.com',
  'cutt.ly',
  'rb.gy',
  'bl.ink',
  'rebrand.ly',
  'shorturl.at',
  'soo.gd',
  'v.gd',
  'trib.al',
  'hyperurl.co',
]);

export function analyzeRedirects(domainInfo) {
  const { hostname, registrableDomain } = domainInfo;
  const isShortener = KNOWN_SHORTENERS.has(hostname) || (registrableDomain && KNOWN_SHORTENERS.has(registrableDomain));

  return {
    isShortener,
    shortenerService: isShortener ? (registrableDomain || hostname) : null,
    remoteExpansionPerformed: false,
    reasonNotExpanded: 'Safe by Design: Remote server-side HTTP redirect fetching is disabled to protect against Server-Side Request Forgery (SSRF) and time-of-check vulnerabilities.',
  };
}

