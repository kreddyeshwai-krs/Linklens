import { parse } from 'tldts';

// High-value brand names targeted by phishing campaigns
const TARGET_BRANDS = [
  'microsoft',
  'google',
  'apple',
  'paypal',
  'amazon',
  'netflix',
  'chase',
  'bankofamerica',
  'wellsfargo',
  'citibank',
  'facebook',
  'instagram',
  'whatsapp',
  'linkedin',
  'twitter',
  'github',
  'dropbox',
  'adobe',
  'binance',
  'coinbase',
  'metamask',
  'walmart',
  'fedex',
  'dhl',
  'usps',
  'ups',
];

/**
 * Calculate Levenshtein distance between two strings
 */
function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));

  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      // deletion
        matrix[i][j - 1] + 1,      // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return matrix[a.length][b.length];
}

/**
 * Replace common visual character substitutions
 * e.g., 'paypa1' -> 'paypal', 'micros0ft' -> 'microsoft'
 */
function normalizeVisualSubstitutions(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/8/g, 'b')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm');
}

export function analyzeDomain(hostname) {
  const parsed = parse(hostname, { allowIcannDomains: true, allowPrivateDomains: false });

  const isIp = Boolean(parsed.isIp);
  const registrableDomain = parsed.domain || null;
  const publicSuffix = parsed.publicSuffix || null;
  const subdomain = parsed.subdomain || null;

  // Extract Second Level Domain / core name (e.g., 'example' from 'example.com')
  let sld = null;
  if (registrableDomain && publicSuffix) {
    const sldPart = registrableDomain.replace(new RegExp(`\\.${publicSuffix}$`), '');
    sld = sldPart.toLowerCase();
  }

  // Punycode & IDN detection
  const isPunycode = hostname.includes('xn--');

  // Lookalike & Typo-squatting checks
  const lookalikeMatches = [];
  const brandSubdomainImpersonation = [];

  const candidatesToCheck = [];
  if (sld) candidatesToCheck.push({ token: sld, source: 'sld' });

  const subdomainParts = subdomain ? subdomain.split('.').filter(Boolean) : [];
  for (const part of subdomainParts) {
    // split subparts by hyphen if present
    const subTokens = part.split('-').filter(Boolean);
    for (const t of subTokens) {
      candidatesToCheck.push({ token: t.toLowerCase(), source: 'subdomain' });
    }
  }

  for (const { token, source } of candidatesToCheck) {
    const normalizedToken = normalizeVisualSubstitutions(token);

    for (const brand of TARGET_BRANDS) {
      // 1. Visual substitution match (e.g. paypa1 -> paypal)
      if (normalizedToken === brand && token !== brand) {
        lookalikeMatches.push({
          targetBrand: brand,
          token,
          source,
          type: 'visual_substitution',
          evidence: `The ${source} token '${token}' visually mimics brand '${brand}' via character substitution.`,
        });
        continue;
      }

      // 2. Levenshtein edit distance check (1 edit away, or 2 for long brands)
      if (token !== brand && brand.length >= 5 && token.length >= 4) {
        const dist = levenshteinDistance(token, brand);
        if (dist === 1 || (dist === 2 && brand.length >= 7)) {
          lookalikeMatches.push({
            targetBrand: brand,
            token,
            source,
            type: 'edit_distance',
            distance: dist,
            evidence: `The ${source} token '${token}' has an edit distance of ${dist} from target brand '${brand}'.`,
          });
        }
      }

      // 3. Brand prefixed with keywords in sld (e.g. microsoft-security)
      if (source === 'sld' && token.includes(brand) && token !== brand) {
        lookalikeMatches.push({
          targetBrand: brand,
          token,
          source,
          type: 'brand_keyword_combination',
          evidence: `The domain '${token}' embeds target brand '${brand}' with extra tokens.`,
        });
      }
    }
  }

  // Brand embedded in subdomains (e.g. login.microsoft.com.attacker.example.com)
  if (subdomain) {
    const subLower = subdomain.toLowerCase();
    for (const brand of TARGET_BRANDS) {
      if (subLower.includes(brand) && (!registrableDomain || !registrableDomain.includes(brand))) {
        brandSubdomainImpersonation.push({
          targetBrand: brand,
          evidence: `Subdomain '${subdomain}' prominently features brand name '${brand}' while the true destination domain is '${registrableDomain}'.`,
        });
      }
    }
  }

  const subdomainDepth = subdomainParts.length;

  return {
    hostname,
    isIp,
    registrableDomain,
    publicSuffix,
    subdomain,
    subdomainDepth,
    sld,
    isPunycode,
    lookalikeMatches,
    brandSubdomainImpersonation,
  };
}