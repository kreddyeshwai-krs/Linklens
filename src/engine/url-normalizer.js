/**
 * URL Normalizer & Sensitive Data Redactor
 * Safely strips authentication credentials and redacts sensitive query values
 * before storing, displaying, or analyzing.
 */

const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'auth',
  'authorization',
  'key',
  'apikey',
  'api_key',
  'secret',
  'password',
  'pwd',
  'pass',
  'code',
  'oauth_token',
  'session',
  'session_id',
  'sid',
  'signature',
  'sig',
  'credentials',
]);

export function normalizeUrl(urlObject) {
  // Clone to avoid mutating input
  const url = new URL(urlObject.toString());

  const hadCredentials = Boolean(url.username || url.password);
  // Strip HTTP basic credentials
  url.username = '';
  url.password = '';

  const redactedParams = [];
  const searchParams = new URLSearchParams(url.search);

  for (const [key, value] of Array.from(searchParams.entries())) {
    const lowerKey = key.toLowerCase();
    if (
      SENSITIVE_QUERY_PARAMS.has(lowerKey) ||
      lowerKey.includes('secret') ||
      lowerKey.includes('token') ||
      lowerKey.includes('password')
    ) {
      redactedParams.push({ key, originalLength: value.length });
      searchParams.set(key, 'REDACTED');
    }
  }

  // Update query string
  url.search = searchParams.toString();

  const normalizedHostname = url.hostname.toLowerCase();
  const redactedUrl = url.toString();

  return {
    rawUrl: urlObject.toString(),
    redactedUrl,
    normalizedHostname,
    protocol: url.protocol,
    port: url.port || (url.protocol === 'https:' ? '443' : '80'),
    pathname: url.pathname,
    search: url.search,
    hash: url.hash,
    hadCredentials,
    redactedParams,
  };
}