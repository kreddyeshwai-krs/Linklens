/**
 * Input validation module for submitted URLs
 * Accepts only valid HTTP and HTTPS URLs.
 * Rejects unsupported schemes, malformed inputs, control characters, and length limits.
 */

const MAX_URL_LENGTH = 2048;
const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

export function validateInput(rawInput) {
  if (typeof rawInput !== 'string') {
    return {
      isValid: false,
      error: 'Input must be a valid string.',
      code: 'INVALID_TYPE',
    };
  }

  const trimmed = rawInput.trim();

  if (!trimmed) {
    return {
      isValid: false,
      error: 'URL cannot be empty.',
      code: 'EMPTY_INPUT',
    };
  }

  if (trimmed.length > MAX_URL_LENGTH) {
    return {
      isValid: false,
      error: `URL exceeds maximum supported length of ${MAX_URL_LENGTH} characters.`,
      code: 'EXCEEDS_MAX_LENGTH',
    };
  }

  // Check for ASCII control characters and null bytes
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    return {
      isValid: false,
      error: 'URL contains invalid control characters or null bytes.',
      code: 'CONTROL_CHARACTERS',
    };
  }

  // Ensure scheme is present; reject relative or protocol-relative URLs without scheme
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (err) {
    return {
      isValid: false,
      error: 'Malformed URL format. Must include a valid protocol (e.g., https://example.com).',
      code: 'MALFORMED_URL',
    };
  }

  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    return {
      isValid: false,
      error: `Unsupported URL protocol '${parsed.protocol}'. Only 'http:' and 'https:' are permitted.`,
      code: 'UNSUPPORTED_SCHEME',
    };
  }

  if (!parsed.hostname || parsed.hostname.length === 0) {
    return {
      isValid: false,
      error: 'URL must contain a valid hostname or domain.',
      code: 'MISSING_HOSTNAME',
    };
  }

  return {
    isValid: true,
    url: trimmed,
    parsed,
  };
}

