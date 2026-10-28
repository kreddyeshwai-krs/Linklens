/**
 * Findings Explainer
 * Converts extracted features and domain checks into human-readable, educational findings.
 */

export function generateFindings({ domainInfo, features, redirectInfo, threatInfo }) {
  const findings = [];

  // 1. IP-literal host
  if (domainInfo.isIp) {
    findings.push({
      ruleId: 'RULE_IP_HOST',
      title: 'Direct IP-Literal Hostname',
      severity: 'high',
      scoreWeight: 30,
      evidence: `The destination uses raw IP address '${domainInfo.hostname}' instead of a verified registered domain.`,
      explanation: 'Legitimate consumer and enterprise web applications almost universally operate under registered domain names with valid SSL/TLS certificates.',
      whyItMatters: 'Attackers use raw IP addresses to bypass domain registration procedures, domain takedowns, and brand reputation filtering.',
      saferAction: 'Do not submit credentials or personal information to websites identified only by raw IP addresses.',
      isHeuristic: true,
    });
  }

  // 2. Punycode / IDN Homoglyph pattern
  if (domainInfo.isPunycode) {
    findings.push({
      ruleId: 'RULE_PUNYCODE_HOMOGLYPH',
      title: 'Punycode / Internationalized Domain Name',
      severity: 'high',
      scoreWeight: 25,
      evidence: `Hostname contains 'xn--' prefix representing internationalized characters: '${domainInfo.hostname}'.`,
      explanation: 'Punycode enables browsers to display non-ASCII characters. Attackers frequently abuse this to display characters that visually imitate standard Latin letters (e.g., Cyrillic "а" imitating Latin "a").',
      whyItMatters: 'A user may see what looks like "apple.com" in their address bar, but the underlying system directs to a completely different registration.',
      saferAction: 'Inspect the address bar carefully or copy the hostname into a plain text editor to verify the ASCII xn-- representation.',
      isHeuristic: true,
    });
  }

  // 3. Lookalike / Typosquatting Match
  if (domainInfo.lookalikeMatches.length > 0) {
    const primaryMatch = domainInfo.lookalikeMatches[0];
    findings.push({
      ruleId: 'RULE_LOOKALIKE_BRAND',
      title: 'Lookalike / Typosquatting Brand Similarity',
      severity: 'critical',
      scoreWeight: 30,
      evidence: primaryMatch.evidence,
      explanation: `The domain name appears intentionally engineered to imitate '${primaryMatch.targetBrand}' using character omissions, substitutions, or deceptive keywords.`,
      whyItMatters: 'Typo-squatting is one of the most pervasive phishing delivery mechanisms, tricking rushed or inattentive users into entering credentials.',
      saferAction: 'Close the link and navigate to the intended organization directly via a known bookmark or direct manual entry of the verified domain.',
      isHeuristic: true,
    });
  }

  // 4. Brand in Subdomain Impersonation
  if (domainInfo.brandSubdomainImpersonation.length > 0) {
    const subMatch = domainInfo.brandSubdomainImpersonation[0];
    findings.push({
      ruleId: 'RULE_BRAND_SUBDOMAIN_DECEPTION',
      title: 'Brand Impersonation in Subdomain',
      severity: 'critical',
      scoreWeight: 30,
      evidence: subMatch.evidence,
      explanation: `The subdomain contains the brand '${subMatch.targetBrand}', but the actual registrable domain receiving the traffic is '${domainInfo.registrableDomain}'.`,
      whyItMatters: 'Anyone can configure subdomains on a domain they control. Attackers create subdomains like "paypal.com.account-update.xyz" knowing victims read left-to-right.',
      saferAction: 'Focus on the registrable domain immediately preceding the primary TLD and the first single forward slash to determine who actually runs the site.',
      isHeuristic: true,
    });
  }

  // 5. Unencrypted HTTP Protocol
  if (features.isPlainHttp) {
    findings.push({
      ruleId: 'RULE_UNENCRYPTED_HTTP',
      title: 'Unencrypted HTTP Connection',
      severity: 'medium',
      scoreWeight: 15,
      evidence: 'The URL uses unencrypted "http://" instead of "https://".',
      explanation: 'Traffic sent over plain HTTP is transmitted in clear text across the network without encryption or cryptographic server authentication.',
      whyItMatters: 'Any entity on the local Wi-Fi, internet service provider, or transit route can eavesdrop on credentials, session tokens, or modify web page content in transit.',
      saferAction: 'Never enter usernames, passwords, or payment cards on unencrypted HTTP websites.',
      isHeuristic: true,
    });
  }

  // 6. HTTPS Mitigating / Educational Indicator
  if (features.isHttps) {
    findings.push({
      ruleId: 'RULE_HTTPS_TRANSPORT_ONLY',
      title: 'HTTPS Active (Transport Encryption Only)',
      severity: 'info',
      scoreWeight: 0,
      evidence: 'Connection uses TLS/HTTPS transport layer encryption.',
      explanation: 'HTTPS provides transport encryption and integrity between your browser and the remote server. However, modern phishing websites routinely obtain free, legitimate SSL certificates.',
      whyItMatters: 'A padlock icon in the browser does NOT prove that a website is genuine or benevolent—only that the connection is encrypted.',
      saferAction: 'Verify the identity of the registrable domain name even if the green lock or HTTPS indicator is present.',
      isHeuristic: true,
    });
  }

  // 7. URL Shortener Masking
  if (redirectInfo.isShortener) {
    findings.push({
      ruleId: 'RULE_URL_SHORTENER_MASK',
      title: 'Opaque URL Shortener Masking Destination',
      severity: 'medium',
      scoreWeight: 15,
      evidence: `Hosted on URL shortening service '${redirectInfo.shortenerService}'.`,
      explanation: 'Shorteners obscure the destination hostname, protocol, and path, preventing safety inspection before connection.',
      whyItMatters: 'Phishers and malware distributors utilize shorteners to bypass initial corporate email filters and deceive users.',
      saferAction: 'Use an online URL unshortener or preview tool before clicking on shortened links received via unexpected emails or text messages.',
      isHeuristic: true,
    });
  }

  // 8. Open Redirect Parameters
  if (features.redirectParamsFound.length > 0) {
    const hasExternal = features.redirectParamsFound.some(p => p.pointsToExternal);
    findings.push({
      ruleId: 'RULE_SUSPICIOUS_REDIRECT_PARAMS',
      title: 'Potential Open Redirect Parameter',
      severity: hasExternal ? 'high' : 'medium',
      scoreWeight: hasExternal ? 20 : 10,
      evidence: `Found query parameters commonly used for post-login redirection: ${features.redirectParamsFound.map(p => `${p.param}=${p.valuePreview}`).join(', ')}.`,
      explanation: 'Parameters like "redirect_url", "return_to", or "url" can be manipulated to bounce a user from a legitimate trusted portal to an attacker harvesting site.',
      whyItMatters: 'Victims may see a trusted company URL initially, click it, and be silently redirected to a credential-harvesting landing page.',
      saferAction: 'Check the URL after logging in to verify you remained on the legitimate organization domain.',
      isHeuristic: true,
    });
  }

  // 9. Obfuscated or Nested Percent-Encoding
  if (features.hasEncodedDelimiters || features.percentCount >= 3) {
    findings.push({
      ruleId: 'RULE_OBFUSCATED_ENCODING',
      title: 'Unusual or Obfuscated Percent-Encoding',
      severity: 'medium',
      scoreWeight: 12,
      evidence: `Contains ${features.percentCount} percent-encoded tokens and/or encoded path delimiters (%2f, %2e).`,
      explanation: 'Percent-encoding (%xx) represents non-standard characters in URLs. Encoding path separators like "/" (%2f) or "." (%2e) is a known technique to evade web application firewalls and keyword detection.',
      whyItMatters: 'Attackers disguise directory traversal attacks, target payloads, or deceptive file extensions through character encoding.',
      saferAction: 'Inspect decoded destination parameters carefully before proceeding.',
      isHeuristic: true,
    });
  }

  // 10. Suspicious Login / Urgency Keywords
  if (features.matchedKeywords.length >= 2) {
    findings.push({
      ruleId: 'RULE_SUSPICIOUS_KEYWORDS',
      title: 'Multiple Login / Account Urgency Keywords',
      severity: 'low',
      scoreWeight: 8,
      evidence: `Detected keywords associated with account authentication or urgent action: ${features.matchedKeywords.slice(0, 4).join(', ')}.`,
      explanation: 'While legitimate web applications naturally use words like "login" and "verify", phishing lures disproportionately pair these terms with deceptive domain structures.',
      whyItMatters: 'Social engineering attacks rely on creating urgency around account suspensions, security alerts, and verification.',
      saferAction: 'Confirm whether this link was prompted by an action you initiated yourself.',
      isHeuristic: true,
    });
  }

  // 11. Excessive Hostname Complexity
  if (domainInfo.subdomainDepth >= 4 || features.isExcessiveHostLength) {
    findings.push({
      ruleId: 'RULE_EXCESSIVE_SUBDOMAINS',
      title: 'Excessive Hostname Complexity & Depth',
      severity: 'medium',
      scoreWeight: 10,
      evidence: `Hostname contains ${domainInfo.subdomainDepth} subdomain levels with a total host length of ${features.hostLength} characters.`,
      explanation: 'Excessive subdomain depth is often used to push the real registrable domain out of view on mobile screens and browser address bars.',
      whyItMatters: 'Mobile address bars frequently truncate lengthy hostnames, hiding the actual domain from view.',
      saferAction: 'On mobile devices, tap or expand the address bar to inspect the complete hostname.',
      isHeuristic: true,
    });
  }

  // 12. External Threat Intelligence Confirmed Match
  if (threatInfo && threatInfo.isThreat) {
    findings.push({
      ruleId: 'RULE_CONFIRMED_THREAT_INTEL',
      title: `Confirmed Malicious Match (${threatInfo.provider})`,
      severity: 'critical',
      scoreWeight: 50,
      evidence: threatInfo.details,
      explanation: `The external threat intelligence provider '${threatInfo.provider}' identified this specific URL as an active threat (${threatInfo.threatType || 'Malicious'}).`,
      whyItMatters: 'Confirmed threat intelligence matches represent known infrastructure previously reported by security research organizations.',
      saferAction: 'DO NOT visit this destination. Discard or report the communication to your security team.',
      isHeuristic: false,
    });
  }

  return findings;
}

