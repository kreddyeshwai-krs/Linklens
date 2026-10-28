-- Link Lens: 003_seed_data.sql
-- Realistic, safe educational scenarios using reserved domains (RFC 2606 / RFC 6761)

-- 1. Insert Educational Learning Scenarios
INSERT INTO public.learning_scenarios (
    id, title, description, difficulty, category, sample_url, 
    public_explanation, correct_indicators, safer_action, enabled, version
) VALUES
(
    '00000000-0000-0000-0000-000000000001',
    'Deceptive Subdomain Masquerading as Bank Portal',
    'Examine how attackers construct deceptive subdomains that feature a well-known institution name in front of an unrelated attacker-controlled domain.',
    'beginner',
    'Misleading Subdomains',
    'https://secure-chase.com.account-verification-auth.example.com/login',
    'Attackers frequently prepend a reputable brand name into subdomains (e.g., secure-chase.com) while the actual destination is the registrable domain at the end (example.com).',
    '["secure-chase.com", "account-verification-auth", "example.com"]'::jsonb,
    'Always read the hostname right-to-left from the first single forward slash to identify the true registrable domain (example.com), ignoring prefixed brand names.',
    true,
    1
),
(
    '00000000-0000-0000-0000-000000000002',
    'Lookalike Typosquatting Brand Substitution',
    'Notice visual substitutions where numerals replace similar alphabetical characters (e.g., 0 for O, 1 for l).',
    'beginner',
    'Lookalike Domains',
    'https://paypa1-security-center.example.net/dispute-resolution',
    'The hostname uses numeral 1 instead of lowercase letter l ("paypa1"). This visual trick mimics real brands to fool hurried users.',
    '["paypa1", "security-center"]'::jsonb,
    'Inspect spelling meticulously or navigate directly by typing the verified official URL into your browser bookmark bar.',
    true,
    1
),
(
    '00000000-0000-0000-0000-000000000003',
    'HTTPS Lock Icon False Sense of Security',
    'Recognize that TLS/HTTPS encrypts transport traffic in transit, but does NOT certify the legitimacy or benevolence of the site owner.',
    'intermediate',
    'HTTPS Misconceptions',
    'https://apple-id-suspended-recovery.example.org/verify-credentials',
    'Any attacker can obtain a free, legitimate SSL/TLS certificate. The presence of https:// or the padlock icon merely proves connection encryption, not brand authenticity.',
    '["apple-id-suspended-recovery", "verify-credentials"]'::jsonb,
    'Never treat HTTPS as proof of safety. Always verify the registrable domain itself before entering credentials or sensitive data.',
    true,
    1
),
(
    '00000000-0000-0000-0000-000000000004',
    'Open Redirect Query Parameter Exploit',
    'Observe how an authentic host might be chained to an unverified target destination using redirection parameters.',
    'advanced',
    'Suspicious URL Parameters',
    'https://portal.example.com/oauth/authorize?client_id=crm&redirect_url=https://attacker-harvest.example.net/steal',
    'The URL legitimately points to portal.example.com, but passes an unvalidated redirect_url query parameter pointing to attacker-harvest.example.net.',
    '["redirect_url=https://attacker-harvest.example.net/steal"]'::jsonb,
    'Check query parameters for destination redirect destinations and avoid authenticating when forwarded unexpectedly.',
    true,
    1
),
(
    '00000000-0000-0000-0000-000000000005',
    'Excessive Hex & Unicode Encoding in Path',
    'Detect obfuscation tactics where standard ASCII characters are repeatedly percent-encoded to bypass naive keyword filters.',
    'intermediate',
    'Encoded Characters',
    'https://auth.example.com/%2e%2e%2f%2e%2e%2fadmin%2fcredentials.php',
    'The path contains multiple percent-encoded representations (%2e = ., %2f = /) attempting directory traversal or filter evasion.',
    '["%2e%2e%2f%2e%2e%2fadmin%2fcredentials.php"]'::jsonb,
    'Legitimate web applications rarely require multiple levels of percent-encoded directory path delimiters in user links.',
    true,
    1
),
(
    '00000000-0000-0000-0000-000000000006',
    'Opaque URL Shortener in Urgent Communication',
    'Analyze an unexpanded shortener link masquerading as urgent HR or payroll notification.',
    'beginner',
    'URL Shorteners',
    'https://bit.ly/3SecurityActionRequired',
    'URL shorteners completely mask the destination hostname, protocol, and path, preventing pre-click inspection.',
    '["bit.ly", "3SecurityActionRequired"]'::jsonb,
    'Use preview services (e.g. appending + or using safety scanners) or contact the sender through out-of-band channels before visiting shortened links.',
    true,
    1
),
(
    '00000000-0000-0000-0000-000000000007',
    'Benign Unusual URL: Static CDN Asset Delivery',
    'Distinguish between genuine security anomalies and legitimate high-complexity infrastructure URLs (such as cloud CDNs with version hashes).',
    'intermediate',
    'Benign Complex URLs',
    'https://static-cdn-prod.example.org/bundles/app-v4.8.2-hash98b3c.min.js?env=production&retry=1',
    'While the URL contains multiple dashes, subdomains, and hexadecimal hashes, it follows standard content delivery network asset versioning practices on a known domain.',
    '[]'::jsonb,
    'Look for known asset endpoints (.js, .css, .woff) on authorized enterprise infrastructure rather than flagging all complex query strings as threats.',
    true,
    1
)
ON CONFLICT (id) DO NOTHING;

-- 2. Insert Educational Quizzes
INSERT INTO public.quizzes (id, title, description, difficulty, enabled, version) VALUES
(
    '10000000-0000-0000-0000-000000000001',
    'URL Red Flags & Domain Dissection Fundamentals',
    'Test your knowledge on hostname hierarchy, HTTPS misconceptions, and common visual phishing tricks.',
    'beginner',
    true,
    1
),
(
    '10000000-0000-0000-0000-000000000002',
    'Advanced Obfuscation, Open Redirects & PSL Analysis',
    'Challenge yourself with punycode attacks, open redirect query vectors, and Public Suffix List boundaries.',
    'advanced',
    true,
    1
)
ON CONFLICT (id) DO NOTHING;

-- 3. Insert Quiz Questions
INSERT INTO public.quiz_questions (
    id, quiz_id, question_text, question_type, public_options, correct_answer, explanation, points, order_index, enabled
) VALUES
(
    '20000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000001',
    'In the URL "https://login.microsoft.com.account-auth.example.com/signin", what is the actual destination domain handling the request?',
    'single_choice',
    '[
        {"id": "opt1", "text": "microsoft.com"},
        {"id": "opt2", "text": "login.microsoft.com"},
        {"id": "opt3", "text": "example.com"},
        {"id": "opt4", "text": "account-auth.example.com"}
    ]'::jsonb,
    '["opt3"]'::jsonb,
    'The registrable domain immediately preceding the primary TLD and first single forward slash is "example.com". Everything preceding it are subdomains controlled entirely by example.com owner.',
    10,
    1,
    true
),
(
    '20000000-0000-0000-0000-000000000002',
    '10000000-0000-0000-0000-000000000001',
    'Which of the following statements about HTTPS are TRUE? (Select all that apply)',
    'multiple_choice',
    '[
        {"id": "opt1", "text": "HTTPS ensures all traffic between client and server is encrypted."},
        {"id": "opt2", "text": "HTTPS proves that the website owner is reputable and not running a scam."},
        {"id": "opt3", "text": "Attackers can easily obtain free, valid SSL/TLS certificates for phishing sites."},
        {"id": "opt4", "text": "A browser padlock icon means user credentials cannot be stolen by the destination site."}
    ]'::jsonb,
    '["opt1", "opt3"]'::jsonb,
    'HTTPS provides transport encryption and server verification against certificate records, but malicious websites routinely use valid TLS certificates.',
    15,
    2,
    true
),
(
    '20000000-0000-0000-0000-000000000003',
    '10000000-0000-0000-0000-000000000001',
    'Why is clicking on an opaque shortened link (e.g. bit.ly/xyz) in an unsolicited email considered high risk?',
    'single_choice',
    '[
        {"id": "opt1", "text": "Shortened links always deliver viruses instantly to your operating system."},
        {"id": "opt2", "text": "The true destination hostname and path are obscured, preventing inspection before connection."},
        {"id": "opt3", "text": "Shorteners disable your browser firewall automatically."},
        {"id": "opt4", "text": "URL shorteners only support unencrypted HTTP protocols."}
    ]'::jsonb,
    '["opt2"]'::jsonb,
    'Shorteners conceal the true destination domain, preventing inspection and bypassing basic perimeter reputation filters until expanded.',
    10,
    3,
    true
),
(
    '20000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000002',
    'What cybersecurity risk is associated with Internationalized Domain Names (IDNs) beginning with "xn--"?',
    'single_choice',
    '[
        {"id": "opt1", "text": "Punycode/Homograph attacks where non-Latin characters visually imitate standard Latin characters."},
        {"id": "opt2", "text": "Bypassing TLS certificate handshake protocols."},
        {"id": "opt3", "text": "Buffer overflows in the operating system DNS client."},
        {"id": "opt4", "text": "Automatic execution of remote Shell scripts."}
    ]'::jsonb,
    '["opt1"]'::jsonb,
    'Punycode enables representation of Unicode characters in ASCII. Attackers exploit homoglyphs (e.g., Cyrillic "а" vs Latin "a") to construct indistinguishable lookalike domains.',
    15,
    1,
    true
),
(
    '20000000-0000-0000-0000-000000000005',
    '10000000-0000-0000-0000-000000000002',
    'Which indicators suggest a potential Open Redirect vulnerability in a link? (Select all that apply)',
    'multiple_choice',
    '[
        {"id": "opt1", "text": "Query parameter named \"redirect\", \"next\", \"return_to\", or \"url\" pointing to an external domain."},
        {"id": "opt2", "text": "Double slash \"//\" or \"https://\" embedded inside the query parameters."},
        {"id": "opt3", "text": "The URL uses standard port 443 with HTTPS."},
        {"id": "opt4", "text": "Presence of a sub-resource integrity hash."}
    ]'::jsonb,
    '["opt1", "opt2"]'::jsonb,
    'Open redirect indicators involve destination parameters (return_to, redirect, dest) containing full external URLs or double-slash protocols designed to redirect the victim after initial visit.',
    15,
    2,
    true
)
ON CONFLICT (id) DO NOTHING;

