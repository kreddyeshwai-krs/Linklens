import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config/index.js';
import { getSupabaseAdmin, isSupabaseActive } from './supabase.js';
import { hashPassword, verifyPassword } from '../utils/crypto.js';

// Local storage path for offline dev persistence
const DATA_DIR = path.resolve(process.cwd(), 'data');
const LOCAL_DB_FILE = path.join(DATA_DIR, 'local-db.json');

// Initial seed scenarios and quizzes
const SEED_SCENARIOS = [
  {
    id: '00000000-0000-0000-0000-000000000001',
    title: 'Deceptive Subdomain Masquerading as Bank Portal',
    description: 'Examine how attackers construct deceptive subdomains featuring a well-known institution name.',
    difficulty: 'beginner',
    category: 'Misleading Subdomains',
    sample_url: 'https://secure-chase.com.account-verification-auth.example.com/login',
    public_explanation: 'Attackers prepend a reputable brand name into subdomains while the actual destination is the registrable domain at the end (example.com).',
    correct_indicators: ['secure-chase.com', 'account-verification-auth', 'example.com'],
    safer_action: 'Always read the hostname right-to-left from the first single forward slash to identify the true registrable domain (example.com).',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '00000000-0000-0000-0000-000000000002',
    title: 'Lookalike Typosquatting Brand Substitution',
    description: 'Notice visual substitutions where numerals replace similar alphabetical characters.',
    difficulty: 'beginner',
    category: 'Lookalike Domains',
    sample_url: 'https://paypa1-security-center.example.net/dispute-resolution',
    public_explanation: 'The hostname uses numeral 1 instead of lowercase letter l ("paypa1").',
    correct_indicators: ['paypa1', 'security-center'],
    safer_action: 'Inspect spelling meticulously or navigate directly by typing the verified official URL.',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '00000000-0000-0000-0000-000000000003',
    title: 'HTTPS Lock Icon False Sense of Security',
    description: 'Recognize that TLS/HTTPS encrypts transport traffic, but does NOT certify site trustworthiness.',
    difficulty: 'intermediate',
    category: 'HTTPS Misconceptions',
    sample_url: 'https://apple-id-suspended-recovery.example.org/verify-credentials',
    public_explanation: 'Any attacker can obtain a free, valid SSL/TLS certificate.',
    correct_indicators: ['apple-id-suspended-recovery', 'verify-credentials'],
    safer_action: 'Never treat HTTPS as proof of safety. Always verify the registrable domain itself.',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '00000000-0000-0000-0000-000000000004',
    title: 'Open Redirect Query Parameter Exploit',
    description: 'Observe how an authentic host might be chained to an unverified target destination.',
    difficulty: 'advanced',
    category: 'Suspicious URL Parameters',
    sample_url: 'https://portal.example.com/oauth/authorize?client_id=crm&redirect_url=https://attacker-harvest.example.net/steal',
    public_explanation: 'The URL legitimately points to portal.example.com, but passes an unvalidated redirect_url.',
    correct_indicators: ['redirect_url=https://attacker-harvest.example.net/steal'],
    safer_action: 'Check query parameters for redirect destinations and avoid authenticating when forwarded unexpectedly.',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '00000000-0000-0000-0000-000000000005',
    title: 'Excessive Hex & Obfuscated Path Encoding',
    description: 'Detect obfuscation tactics where characters are percent-encoded to evade keyword filters.',
    difficulty: 'intermediate',
    category: 'Encoded Characters',
    sample_url: 'https://auth.example.com/%2e%2e%2f%2e%2e%2fadmin%2fcredentials.php',
    public_explanation: 'The path contains percent-encoded directory traversals (%2e = ., %2f = /).',
    correct_indicators: ['%2e%2e%2f%2e%2e%2fadmin%2fcredentials.php'],
    safer_action: 'Legitimate applications rarely require nested percent-encoded directory path delimiters.',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '00000000-0000-0000-0000-000000000006',
    title: 'Opaque URL Shortener in Urgent Message',
    description: 'Analyze an unexpanded shortener link masquerading as urgent communication.',
    difficulty: 'beginner',
    category: 'URL Shorteners',
    sample_url: 'https://bit.ly/3SecurityActionRequired',
    public_explanation: 'URL shorteners completely mask the destination hostname, protocol, and path.',
    correct_indicators: ['bit.ly', '3SecurityActionRequired'],
    safer_action: 'Use link previewers or contact the sender through verified out-of-band channels.',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '00000000-0000-0000-0000-000000000007',
    title: 'Benign Unusual URL: Static CDN Asset Delivery',
    description: 'Distinguish between genuine security anomalies and legitimate high-complexity infrastructure URLs.',
    difficulty: 'intermediate',
    category: 'Benign Complex URLs',
    sample_url: 'https://static-cdn-prod.example.org/bundles/app-v4.8.2-hash98b3c.min.js?env=production&retry=1',
    public_explanation: 'While the URL contains multiple dashes and hashes, it follows standard CDN versioning practices.',
    correct_indicators: [],
    safer_action: 'Look for known asset endpoints (.js, .css) on verified enterprise infrastructure.',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

const SEED_QUIZZES = [
  {
    id: '10000000-0000-0000-0000-000000000001',
    title: 'URL Red Flags & Domain Dissection Fundamentals',
    description: 'Test your knowledge on hostname hierarchy, HTTPS misconceptions, and common phishing tricks.',
    difficulty: 'beginner',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
  },
  {
    id: '10000000-0000-0000-0000-000000000002',
    title: 'Advanced Obfuscation, Open Redirects & PSL Analysis',
    description: 'Challenge yourself with punycode attacks, open redirect vectors, and Public Suffix List boundaries.',
    difficulty: 'advanced',
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
  },
];

const SEED_QUESTIONS = [
  {
    id: '20000000-0000-0000-0000-000000000001',
    quiz_id: '10000000-0000-0000-0000-000000000001',
    question_text: 'In the URL "https://login.microsoft.com.account-auth.example.com/signin", what is the actual destination domain handling the request?',
    question_type: 'single_choice',
    public_options: [
      { id: 'opt1', text: 'microsoft.com' },
      { id: 'opt2', text: 'login.microsoft.com' },
      { id: 'opt3', text: 'example.com' },
      { id: 'opt4', text: 'account-auth.example.com' },
    ],
    correct_answer: ['opt3'],
    explanation: 'The registrable domain immediately preceding the primary TLD and first single forward slash is "example.com". Everything preceding it are subdomains controlled entirely by example.com owner.',
    points: 10,
    order_index: 1,
    enabled: true,
  },
  {
    id: '20000000-0000-0000-0000-000000000002',
    quiz_id: '10000000-0000-0000-0000-000000000001',
    question_text: 'Which of the following statements about HTTPS are TRUE? (Select all that apply)',
    question_type: 'multiple_choice',
    public_options: [
      { id: 'opt1', text: 'HTTPS ensures all traffic between client and server is encrypted.' },
      { id: 'opt2', text: 'HTTPS proves that the website owner is reputable and not running a scam.' },
      { id: 'opt3', text: 'Attackers can easily obtain free, valid SSL/TLS certificates for phishing sites.' },
      { id: 'opt4', text: 'A browser padlock icon means user credentials cannot be stolen by the destination site.' },
    ],
    correct_answer: ['opt1', 'opt3'],
    explanation: 'HTTPS provides transport encryption, but malicious websites routinely obtain and use valid TLS certificates.',
    points: 15,
    order_index: 2,
    enabled: true,
  },
  {
    id: '20000000-0000-0000-0000-000000000003',
    quiz_id: '10000000-0000-0000-0000-000000000001',
    question_text: 'Why is clicking on an opaque shortened link (e.g. bit.ly/xyz) in an unsolicited email considered high risk?',
    question_type: 'single_choice',
    public_options: [
      { id: 'opt1', text: 'Shortened links always deliver viruses instantly.' },
      { id: 'opt2', text: 'The true destination hostname and path are obscured, preventing inspection before connection.' },
      { id: 'opt3', text: 'Shorteners disable your browser firewall.' },
      { id: 'opt4', text: 'URL shorteners only support unencrypted HTTP.' },
    ],
    correct_answer: ['opt2'],
    explanation: 'Shorteners conceal the true destination domain, preventing inspection and bypassing basic reputation filters.',
    points: 10,
    order_index: 3,
    enabled: true,
  },
  {
    id: '20000000-0000-0000-0000-000000000004',
    quiz_id: '10000000-0000-0000-0000-000000000002',
    question_text: 'What cybersecurity risk is associated with Internationalized Domain Names (IDNs) beginning with "xn--"?',
    question_type: 'single_choice',
    public_options: [
      { id: 'opt1', text: 'Punycode/Homograph attacks where non-Latin characters visually imitate standard Latin characters.' },
      { id: 'opt2', text: 'Bypassing TLS certificate handshake protocols.' },
      { id: 'opt3', text: 'Buffer overflows in the operating system DNS client.' },
      { id: 'opt4', text: 'Automatic execution of remote Shell scripts.' },
    ],
    correct_answer: ['opt1'],
    explanation: 'Punycode allows representation of Unicode characters in ASCII. Attackers exploit homoglyphs to craft deceptive lookalike domains.',
    points: 15,
    order_index: 1,
    enabled: true,
  },
  {
    id: '20000000-0000-0000-0000-000000000005',
    quiz_id: '10000000-0000-0000-0000-000000000002',
    question_text: 'Which indicators suggest a potential Open Redirect vulnerability in a link? (Select all that apply)',
    question_type: 'multiple_choice',
    public_options: [
      { id: 'opt1', text: 'Query parameter named "redirect", "next", "return_to", or "url" pointing to an external domain.' },
      { id: 'opt2', text: 'Double slash "//" or "https://" embedded inside query parameters.' },
      { id: 'opt3', text: 'The URL uses standard port 443 with HTTPS.' },
      { id: 'opt4', text: 'Presence of a sub-resource integrity hash.' },
    ],
    correct_answer: ['opt1', 'opt2'],
    explanation: 'Open redirect indicators involve destination parameters (return_to, redirect, dest) containing full external URLs or double slashes.',
    points: 15,
    order_index: 2,
    enabled: true,
  },
];

// Initialize local in-memory/file storage
class LocalStore {
  constructor() {
    this.state = {
      users: [],
      profiles: [],
      scans: [],
      learning_scenarios: [...SEED_SCENARIOS],
      learning_attempts: [],
      quizzes: [...SEED_QUIZZES],
      quiz_questions: [...SEED_QUESTIONS],
      quiz_attempts: [],
      admin_audit_logs: [],
    };
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(LOCAL_DB_FILE)) {
        const raw = fs.readFileSync(LOCAL_DB_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        this.state = {
          ...this.state,
          ...parsed,
          learning_scenarios: parsed.learning_scenarios?.length ? parsed.learning_scenarios : [...SEED_SCENARIOS],
          quizzes: parsed.quizzes?.length ? parsed.quizzes : [...SEED_QUIZZES],
          quiz_questions: parsed.quiz_questions?.length ? parsed.quiz_questions : [...SEED_QUESTIONS],
        };
      }
    } catch (e) {
      // fallback to initial state
    }
  }

  save() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(LOCAL_DB_FILE, JSON.stringify(this.state, null, 2), 'utf-8');
    } catch (e) {
      // silently ignore write errors in constrained test envs
    }
  }
}

const localStore = new LocalStore();

export const db = {
  /**
   * Reset local state (useful for test isolation)
   */
  async resetForTesting() {
    localStore.state = {
      users: [],
      profiles: [],
      scans: [],
      learning_scenarios: [...SEED_SCENARIOS],
      learning_attempts: [],
      quizzes: [...SEED_QUIZZES],
      quiz_questions: [...SEED_QUESTIONS],
      quiz_attempts: [],
      admin_audit_logs: [],
    };
    localStore.save();
  },

  // ==========================================
  // USERS & PROFILES
  // ==========================================

  async createUser({ email, password, displayName, role = 'user' }) {
    const existing = await this.getUserByEmail(email);
    if (existing) {
      throw new Error('User already exists with this email address');
    }

    const userId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    const now = new Date().toISOString();

    const user = {
      id: userId,
      email: email.toLowerCase(),
      password_hash: passwordHash,
      created_at: now,
    };

    const profile = {
      id: userId,
      email: email.toLowerCase(),
      display_name: displayName || email.split('@')[0],
      role: role === 'admin' ? 'admin' : 'user',
      theme_preference: 'system',
      created_at: now,
      updated_at: now,
    };

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      // Supabase Auth signup
      const { data: authData, error: authError } = await admin.auth.admin.createUser({
        email: email.toLowerCase(),
        password,
        email_confirm: true,
        user_metadata: { display_name: profile.display_name },
      });
      if (authError || !authData?.user) {
        throw new Error(authError?.message || 'Failed to create user in Supabase');
      }

      const realId = authData.user.id;
      profile.id = realId;
      profile.email = email.toLowerCase();

      const { error: profileError } = await admin
        .from('profiles')
        .upsert(profile);
      if (profileError) throw new Error(profileError.message);

      return { id: realId, email: email.toLowerCase(), ...profile };
    }

    localStore.state.users.push(user);
    localStore.state.profiles.push(profile);
    localStore.save();

    return { id: userId, email: user.email, ...profile };
  },

  async getUserByEmail(email) {
    if (!email) return null;
    const cleanEmail = email.toLowerCase().trim();

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      // First try direct lookup in profiles by email
      const { data: profileByEmail, error: pErr } = await admin
        .from('profiles')
        .select('*')
        .eq('email', cleanEmail)
        .maybeSingle();

      if (!pErr && profileByEmail) {
        return profileByEmail;
      }

      // Fallback to Supabase Auth admin user listing
      const { data: users, error } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
      if (error) throw new Error(error.message);
      const matched = users?.users?.find(u => u.email?.toLowerCase() === cleanEmail);
      if (!matched) return null;

      const profile = await this.getProfileById(matched.id);
      return {
        id: matched.id,
        email: matched.email,
        ...profile,
      };
    }

    const user = localStore.state.users.find(u => u.email === cleanEmail);
    if (!user) return null;
    const profile = localStore.state.profiles.find(p => p.id === user.id) || {};
    return {
      ...user,
      ...profile,
    };
  },

  async authenticateUser(email, password) {
    const cleanEmail = email.toLowerCase().trim();
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin.auth.signInWithPassword({
        email: cleanEmail,
        password,
      });
      if (error || !data?.user) return null;
      const profile = await this.getProfileById(data.user.id);
      return {
        id: data.user.id,
        email: data.user.email,
        session: data.session,
        ...profile,
      };
    }

    const user = localStore.state.users.find(u => u.email === cleanEmail);
    if (!user) return null;

    const isValid = await verifyPassword(user.password_hash, password);
    if (!isValid) return null;

    const profile = localStore.state.profiles.find(p => p.id === user.id) || {};
    return {
      id: user.id,
      email: user.email,
      ...profile,
    };
  },

  async getProfileById(userId) {
    if (!userId) return null;

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin
        .from('profiles')
        .select('*')
        .eq('id', userId)
        .maybeSingle();
      if (error) throw new Error(error.message);
      if (!data) return null;

      // Ensure email is attached if omitted on profile
      if (!data.email) {
        try {
          const { data: userData } = await admin.auth.admin.getUserById(userId);
          if (userData?.user?.email) {
            data.email = userData.user.email;
          }
        } catch (e) {
          // Non-blocking fallback
        }
      }
      return data;
    }

    const profile = localStore.state.profiles.find(p => p.id === userId);
    if (!profile) return null;
    const user = localStore.state.users.find(u => u.id === userId);
    return {
      email: user?.email || profile.email || null,
      ...profile,
    };
  },

  async updateProfile(userId, { displayName, themePreference, role }, actorIsAdmin = false) {
    const profile = await this.getProfileById(userId);
    if (!profile) throw new Error('Profile not found');

    const updates = {
      updated_at: new Date().toISOString(),
    };
    if (displayName !== undefined) updates.display_name = displayName;
    if (themePreference !== undefined) updates.theme_preference = themePreference;

    // Strict RLS check: Only admins can change roles
    if (role !== undefined) {
      if (!actorIsAdmin) {
        throw new Error('Unauthorized: Only administrators can modify roles');
      }
      updates.role = role;
    }

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin
        .from('profiles')
        .update(updates)
        .eq('id', userId)
        .select()
        .single();
      if (error) throw new Error(error.message);
      return data;
    }

    const index = localStore.state.profiles.findIndex(p => p.id === userId);
    localStore.state.profiles[index] = { ...localStore.state.profiles[index], ...updates };
    localStore.save();
    return localStore.state.profiles[index];
  },

  // ==========================================
  // SCANS
  // ==========================================

  async createScan(scanData) {
    const scan = {
      id: scanData.id || crypto.randomUUID(),
      user_id: scanData.user_id,
      submitted_url_redacted: scanData.submitted_url_redacted,
      normalized_hostname: scanData.normalized_hostname,
      registrable_domain: scanData.registrable_domain || null,
      risk_score: scanData.risk_score,
      risk_category: scanData.risk_category,
      confidence_level: scanData.confidence_level || 'Moderate',
      analysis_mode: scanData.analysis_mode || 'real',
      ruleset_version: scanData.ruleset_version,
      findings: scanData.findings || [],
      provider_results: scanData.provider_results || {},
      analyzed_at: scanData.analyzed_at || new Date().toISOString(),
      created_at: new Date().toISOString(),
    };

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin
        .from('scans')
        .insert(scan)
        .select()
        .single();
      if (error) throw new Error(error.message);
      return data;
    }

    localStore.state.scans.unshift(scan);
    localStore.save();
    return scan;
  },

  async getScansByUser(userId, { page = 1, limit = 10, search = '', riskCategory = '' } = {}) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      let query = admin
        .from('scans')
        .select('*', { count: 'exact' })
        .eq('user_id', userId);

      if (riskCategory) {
        query = query.eq('risk_category', riskCategory);
      }
      if (search) {
        const cleanSearch = search.replace(/[,()]/g, ' ').trim();
        if (cleanSearch) {
          query = query.or(`normalized_hostname.ilike.%${cleanSearch}%,submitted_url_redacted.ilike.%${cleanSearch}%`);
        }
      }

      const offset = (page - 1) * limit;
      query = query
        .order('analyzed_at', { ascending: false })
        .range(offset, offset + limit - 1);

      const { data, count, error } = await query;
      if (error) throw new Error(error.message);

      return {
        scans: data || [],
        total: count || 0,
        page,
        limit,
        totalPages: Math.ceil((count || 0) / limit) || 1,
      };
    }

    let items = localStore.state.scans.filter(s => s.user_id === userId);

    if (riskCategory) {
      items = items.filter(s => s.risk_category.toLowerCase() === riskCategory.toLowerCase());
    }
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(s => 
        s.normalized_hostname.toLowerCase().includes(q) ||
        s.submitted_url_redacted.toLowerCase().includes(q)
      );
    }

    const total = items.length;
    const offset = (page - 1) * limit;
    const paginated = items.slice(offset, offset + limit);

    return {
      scans: paginated,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    };
  },

  async getScanById(scanId, userId, isAdmin = false) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      let query = admin.from('scans').select('*').eq('id', scanId);
      if (!isAdmin) {
        query = query.eq('user_id', userId);
      }
      const { data, error } = await query.maybeSingle();
      if (error) throw new Error(error.message);
      return data || null;
    }

    const scan = localStore.state.scans.find(s => s.id === scanId);
    if (!scan) return null;
    if (!isAdmin && scan.user_id !== userId) return null;
    return scan;
  },

  async deleteScan(scanId, userId, isAdmin = false) {
    const scan = await this.getScanById(scanId, userId, isAdmin);
    if (!scan) {
      return false;
    }

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { error } = await admin.from('scans').delete().eq('id', scanId);
      if (error) throw new Error(error.message);
      return true;
    }

    const index = localStore.state.scans.findIndex(s => s.id === scanId);
    if (index !== -1) {
      localStore.state.scans.splice(index, 1);
      localStore.save();
      return true;
    }
    return false;
  },

  async clearUserScans(userId) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { error } = await admin.from('scans').delete().eq('user_id', userId);
      if (error) throw new Error(error.message);
      return true;
    }

    localStore.state.scans = localStore.state.scans.filter(s => s.user_id !== userId);
    localStore.save();
    return true;
  },

  // ==========================================
  // LEARNING SCENARIOS
  // ==========================================

  async getScenarios({ difficulty, enabledOnly = true } = {}) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      let query = admin.from('learning_scenarios').select('id, title, description, difficulty, category, sample_url, public_explanation, safer_action, enabled, version, created_at, updated_at');
      if (enabledOnly) query = query.eq('enabled', true);
      if (difficulty) query = query.eq('difficulty', difficulty);
      const { data, error } = await query.order('created_at', { ascending: true });
      if (error) throw new Error(error.message);
      return data || [];
    }

    let items = localStore.state.learning_scenarios;
    if (enabledOnly) items = items.filter(s => s.enabled);
    if (difficulty) items = items.filter(s => s.difficulty === difficulty);

    // Omit correct_indicators from public output
    return items.map(({ correct_indicators, ...pub }) => pub);
  },

  async getScenarioById(id, includeAnswers = false) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin.from('learning_scenarios').select('*').eq('id', id).maybeSingle();
      if (error) throw new Error(error.message);
      if (!data) return null;
      if (!includeAnswers) {
        const { correct_indicators, ...pub } = data;
        return pub;
      }
      return data;
    }

    const item = localStore.state.learning_scenarios.find(s => s.id === id);
    if (!item) return null;
    if (!includeAnswers) {
      const { correct_indicators, ...pub } = item;
      return pub;
    }
    return item;
  },

  async submitScenarioAnswer(scenarioId, userId, selectedIndicators) {
    const scenario = await this.getScenarioById(scenarioId, true);
    if (!scenario) throw new Error('Scenario not found');

    const expected = scenario.correct_indicators || [];
    const submitted = Array.isArray(selectedIndicators) ? selectedIndicators : [];

    // Evaluate accuracy
    const expectedSet = new Set(expected);
    const submittedSet = new Set(submitted);

    let matchCount = 0;
    for (const item of submittedSet) {
      if (expectedSet.has(item)) matchCount++;
    }

    // Determine correct if benign (expected empty and submitted empty) or selected correct indicators
    let isCorrect = false;
    let score = 0;

    if (expected.length === 0) {
      isCorrect = submitted.length === 0;
      score = isCorrect ? 100 : 0;
    } else {
      const precision = matchCount / Math.max(submittedSet.size, 1);
      const recall = matchCount / expectedSet.size;
      const f1 = (precision + recall > 0) ? (2 * precision * recall) / (precision + recall) : 0;
      score = Math.round(f1 * 100);
      isCorrect = score >= 70;
    }

    const feedback = {
      isCorrect,
      score,
      expectedIndicators: expected,
      explanation: scenario.public_explanation,
      saferAction: scenario.safer_action,
    };

    const attempt = {
      id: crypto.randomUUID(),
      user_id: userId,
      scenario_id: scenarioId,
      submitted_answer: submitted,
      score,
      correct: isCorrect,
      feedback,
      completed_at: new Date().toISOString(),
    };

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin.from('learning_attempts').insert(attempt).select().single();
      if (error) throw new Error(error.message);
      return data;
    }

    localStore.state.learning_attempts.push(attempt);
    localStore.save();
    return attempt;
  },

  async getUserLearningAttempts(userId) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin
        .from('learning_attempts')
        .select('*')
        .eq('user_id', userId)
        .order('completed_at', { ascending: false });
      if (error) throw new Error(error.message);
      return data || [];
    }

    return localStore.state.learning_attempts
      .filter(a => a.user_id === userId)
      .sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at));
  },

  // ==========================================
  // QUIZZES
  // ==========================================

  async getQuizzes({ difficulty, enabledOnly = true } = {}) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      let query = admin.from('quizzes').select('*');
      if (enabledOnly) query = query.eq('enabled', true);
      if (difficulty) query = query.eq('difficulty', difficulty);
      const { data, error } = await query.order('created_at', { ascending: true });
      if (error) throw new Error(error.message);
      return data || [];
    }

    let items = localStore.state.quizzes;
    if (enabledOnly) items = items.filter(q => q.enabled);
    if (difficulty) items = items.filter(q => q.difficulty === difficulty);
    return items;
  },

  async getQuizDetails(quizId) {
    let quiz;
    let questions;

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data: qData, error: qErr } = await admin.from('quizzes').select('*').eq('id', quizId).maybeSingle();
      if (qErr || !qData) return null;
      quiz = qData;

      const { data: questData, error: questErr } = await admin
        .from('quiz_questions')
        .select('id, quiz_id, question_text, question_type, public_options, points, order_index, enabled')
        .eq('quiz_id', quizId)
        .eq('enabled', true)
        .order('order_index', { ascending: true });
      if (questErr) throw new Error(questErr.message);
      questions = questData || [];
    } else {
      quiz = localStore.state.quizzes.find(q => q.id === quizId);
      if (!quiz) return null;
      questions = localStore.state.quiz_questions
        .filter(q => q.quiz_id === quizId && q.enabled)
        .sort((a, b) => a.order_index - b.order_index)
        .map(({ correct_answer, explanation, ...pub }) => pub);
    }

    return { ...quiz, questions };
  },

  async submitQuizAnswers(quizId, userId, answersMap) {
    let questions;
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin
        .from('quiz_questions')
        .select('*')
        .eq('quiz_id', quizId)
        .eq('enabled', true);
      if (error) throw new Error(error.message);
      questions = data || [];
    } else {
      questions = localStore.state.quiz_questions.filter(q => q.quiz_id === quizId && q.enabled);
    }

    if (!questions || questions.length === 0) {
      throw new Error('No questions found for this quiz');
    }

    let totalPoints = 0;
    let earnedPoints = 0;
    const detailedResults = [];

    for (const q of questions) {
      totalPoints += q.points;
      const userSelected = answersMap[q.id] || [];
      const userArr = Array.isArray(userSelected) ? userSelected : [userSelected];
      const correctArr = Array.isArray(q.correct_answer) ? q.correct_answer : [q.correct_answer];

      const isCorrect = userArr.length === correctArr.length &&
        userArr.every(val => correctArr.includes(val)) &&
        correctArr.every(val => userArr.includes(val));

      if (isCorrect) {
        earnedPoints += q.points;
      }

      detailedResults.push({
        questionId: q.id,
        questionText: q.question_text,
        userAnswers: userArr,
        correctAnswers: correctArr,
        isCorrect,
        points: isCorrect ? q.points : 0,
        explanation: q.explanation,
      });
    }

    const percentage = totalPoints > 0 ? Math.round((earnedPoints / totalPoints) * 100) : 0;

    const attempt = {
      id: crypto.randomUUID(),
      user_id: userId,
      quiz_id: quizId,
      score: percentage,
      total_points: earnedPoints,
      answers: detailedResults,
      completed_at: new Date().toISOString(),
    };

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin.from('quiz_attempts').insert(attempt).select().single();
      if (error) throw new Error(error.message);
      return data;
    }

    localStore.state.quiz_attempts.push(attempt);
    localStore.save();
    return attempt;
  },

  async getUserQuizAttempts(userId) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin
        .from('quiz_attempts')
        .select('*, quizzes(title, difficulty)')
        .eq('user_id', userId)
        .order('completed_at', { ascending: false });
      if (error) throw new Error(error.message);
      return data || [];
    }

    return localStore.state.quiz_attempts
      .filter(a => a.user_id === userId)
      .map(a => {
        const quiz = localStore.state.quizzes.find(q => q.id === a.quiz_id) || {};
        return {
          ...a,
          quizzes: { title: quiz.title, difficulty: quiz.difficulty },
        };
      })
      .sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at));
  },

  // ==========================================
  // PROGRESS & ANALYTICS
  // ==========================================

  async getUserProgress(userId) {
    const scansRes = await this.getScansByUser(userId, { limit: 1000 });
    const learningAttempts = await this.getUserLearningAttempts(userId);
    const quizAttempts = await this.getUserQuizAttempts(userId);

    const totalScans = scansRes.total;
    const completedScenarios = new Set(learningAttempts.filter(a => a.correct).map(a => a.scenario_id)).size;
    const totalScenarios = (await this.getScenarios({ enabledOnly: true })).length;
    
    const passedQuizzes = new Set(quizAttempts.filter(a => a.score >= 70).map(a => a.quiz_id)).size;
    const totalQuizzes = (await this.getQuizzes({ enabledOnly: true })).length;

    // Badges calculation
    const badges = [];
    if (totalScans >= 1) badges.push({ id: 'first_scan', title: 'First Red Flag Scan', icon: '🔍', desc: 'Analyzed your first live URL' });
    if (totalScans >= 10) badges.push({ id: 'veteran_scanner', title: 'URL Inspector', icon: '🛡️', desc: 'Analyzed 10 or more URLs' });
    if (completedScenarios >= 3) badges.push({ id: 'scenario_novice', title: 'Red Flag Sleuth', icon: '🎯', desc: 'Successfully solved 3 scenarios' });
    if (completedScenarios >= totalScenarios && totalScenarios > 0) badges.push({ id: 'scenario_master', title: 'Simulator Champion', icon: '🏆', desc: 'Mastered all simulation exercises' });
    if (passedQuizzes >= 1) badges.push({ id: 'quiz_pass', title: 'Certified Analyst', icon: '📜', desc: 'Passed a cybersecurity quiz with 70%+' });

    return {
      totalScans,
      completedScenarios,
      totalScenarios,
      passedQuizzes,
      totalQuizzes,
      learningProgressPct: totalScenarios > 0 ? Math.round((completedScenarios / totalScenarios) * 100) : 0,
      quizProgressPct: totalQuizzes > 0 ? Math.round((passedQuizzes / totalQuizzes) * 100) : 0,
      badges,
      recentScans: scansRes.scans.slice(0, 5),
      recentQuizAttempts: quizAttempts.slice(0, 3),
    };
  },

  // ==========================================
  // ADMIN SERVICE & AUDIT LOGS
  // ==========================================

  async createAuditLog({ actorUserId, action, targetType, targetId, metadata = {} }) {
    const log = {
      id: crypto.randomUUID(),
      actor_user_id: actorUserId,
      action,
      target_type: targetType,
      target_id: targetId,
      metadata,
      created_at: new Date().toISOString(),
    };

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { error } = await admin.from('admin_audit_logs').insert(log);
      if (error) console.error('Audit log failed:', error.message);
      return log;
    }

    localStore.state.admin_audit_logs.unshift(log);
    localStore.save();
    return log;
  },

  async getAdminOverview() {
    let totalUsers = 0;
    let totalScans = 0;
    let totalAttempts = 0;
    let riskStats = { Low: 0, Moderate: 0, High: 0, Critical: 0 };

    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { count: uCount } = await admin.from('profiles').select('*', { count: 'exact', head: true });
      totalUsers = uCount || 0;

      const { count: sCount } = await admin.from('scans').select('*', { count: 'exact', head: true });
      totalScans = sCount || 0;

      const { data: scans } = await admin.from('scans').select('risk_category').limit(1000);
      if (scans) {
        for (const s of scans) {
          if (riskStats[s.risk_category] !== undefined) riskStats[s.risk_category]++;
        }
      }

      const { count: aCount } = await admin.from('learning_attempts').select('*', { count: 'exact', head: true });
      totalAttempts = aCount || 0;
    } else {
      totalUsers = localStore.state.profiles.length;
      totalScans = localStore.state.scans.length;
      totalAttempts = localStore.state.learning_attempts.length + localStore.state.quiz_attempts.length;
      for (const s of localStore.state.scans) {
        if (riskStats[s.risk_category] !== undefined) riskStats[s.risk_category]++;
      }
    }

    return {
      totalUsers,
      totalScans,
      totalAttempts,
      riskStats,
    };
  },

  async getAdminScans({ page = 1, limit = 20 } = {}) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const offset = (page - 1) * limit;
      const { data, count, error } = await admin
        .from('scans')
        .select('id, user_id, submitted_url_redacted, normalized_hostname, risk_score, risk_category, analyzed_at, profiles(display_name)', { count: 'exact' })
        .order('analyzed_at', { ascending: false })
        .range(offset, offset + limit - 1);
      if (error) throw new Error(error.message);
      return { scans: data || [], total: count || 0, page, limit };
    }

    const offset = (page - 1) * limit;
    const items = localStore.state.scans.slice(offset, offset + limit).map(s => {
      const profile = localStore.state.profiles.find(p => p.id === s.user_id) || {};
      return {
        ...s,
        profiles: { display_name: profile.display_name || 'Anonymous' },
      };
    });
    return {
      scans: items,
      total: localStore.state.scans.length,
      page,
      limit,
    };
  },

  async getAdminAuditLogs({ page = 1, limit = 20 } = {}) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const offset = (page - 1) * limit;
      const { data, count, error } = await admin
        .from('admin_audit_logs')
        .select('*', { count: 'exact' })
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1);
      if (error) throw new Error(error.message);
      return { logs: data || [], total: count || 0, page, limit };
    }

    const offset = (page - 1) * limit;
    return {
      logs: localStore.state.admin_audit_logs.slice(offset, offset + limit),
      total: localStore.state.admin_audit_logs.length,
      page,
      limit,
    };
  },

  async toggleScenario(id, enabled, actorUserId) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin
        .from('learning_scenarios')
        .update({ enabled, updated_at: new Date().toISOString() })
        .eq('id', id)
        .select()
        .single();
      if (error) throw new Error(error.message);
      await this.createAuditLog({
        actorUserId,
        action: 'TOGGLE_SCENARIO',
        targetType: 'learning_scenarios',
        targetId: id,
        metadata: { enabled },
      });
      return data;
    }

    const item = localStore.state.learning_scenarios.find(s => s.id === id);
    if (!item) throw new Error('Scenario not found');
    item.enabled = enabled;
    item.updated_at = new Date().toISOString();
    localStore.save();

    await this.createAuditLog({
      actorUserId,
      action: 'TOGGLE_SCENARIO',
      targetType: 'learning_scenarios',
      targetId: id,
      metadata: { enabled },
    });
    return item;
  },

  async toggleQuiz(id, enabled, actorUserId) {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      const { data, error } = await admin
        .from('quizzes')
        .update({ enabled })
        .eq('id', id)
        .select()
        .single();
      if (error) throw new Error(error.message);
      await this.createAuditLog({
        actorUserId,
        action: 'TOGGLE_QUIZ',
        targetType: 'quizzes',
        targetId: id,
        metadata: { enabled },
      });
      return data;
    }

    const item = localStore.state.quizzes.find(q => q.id === id);
    if (!item) throw new Error('Quiz not found');
    item.enabled = enabled;
    localStore.save();

    await this.createAuditLog({
      actorUserId,
      action: 'TOGGLE_QUIZ',
      targetType: 'quizzes',
      targetId: id,
      metadata: { enabled },
    });
    return item;
  },

  async seedInitialDataIfNeeded() {
    if (isSupabaseActive()) {
      const admin = getSupabaseAdmin();
      if (!admin) return;

      // Seed learning scenarios if empty
      const { count: scnCount } = await admin.from('learning_scenarios').select('*', { count: 'exact', head: true });
      if (!scnCount || scnCount === 0) {
        await admin.from('learning_scenarios').upsert(SEED_SCENARIOS);
      }

      // Seed quizzes if empty
      const { count: qzCount } = await admin.from('quizzes').select('*', { count: 'exact', head: true });
      if (!qzCount || qzCount === 0) {
        await admin.from('quizzes').upsert(SEED_QUIZZES);
      }

      // Seed quiz questions if empty
      const { count: qqCount } = await admin.from('quiz_questions').select('*', { count: 'exact', head: true });
      if (!qqCount || qqCount === 0) {
        await admin.from('quiz_questions').upsert(SEED_QUESTIONS);
      }
    }
  },
};

