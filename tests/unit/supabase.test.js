import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { getSupabase, getSupabaseAdmin, isSupabaseActive, hasServiceRole } from '../../src/services/supabase.js';
import { extractUserFromToken } from '../../src/middleware/auth.js';
import { db } from '../../src/services/db.js';
import { signJwt } from '../../src/utils/jwt.js';

describe('Supabase Service & Auth Integration Unit Tests', () => {
  before(async () => {
    await db.resetForTesting();
  });

  describe('Client Management & Resilience', () => {
    it('provides safe getters for public and admin clients', () => {
      // In offline/local mode without SUPABASE_URL configured
      const pub = getSupabase();
      const admin = getSupabaseAdmin();
      assert.equal(typeof isSupabaseActive(), 'boolean');
      assert.equal(typeof hasServiceRole(), 'boolean');
      // Should not throw or crash
      assert.ok(pub === null || typeof pub === 'object');
      assert.ok(admin === null || typeof admin === 'object');
    });
  });

  describe('User Profile & Email Synchronization', () => {
    it('persists and returns email on user creation and profile retrieval', async () => {
      const user = await db.createUser({
        email: 'analyst.sync@example.com',
        password: 'ValidSecurePassword123!',
        displayName: 'Sync Analyst',
        role: 'user',
      });

      assert.equal(user.email, 'analyst.sync@example.com');
      assert.equal(user.role, 'user');

      const profile = await db.getProfileById(user.id);
      assert.ok(profile);
      assert.equal(profile.email, 'analyst.sync@example.com');
      assert.equal(profile.display_name, 'Sync Analyst');
    });

    it('retrieves user by email accurately', async () => {
      const found = await db.getUserByEmail('analyst.sync@example.com');
      assert.ok(found);
      assert.equal(found.email, 'analyst.sync@example.com');
    });
  });

  describe('Token Verification & User Extraction', () => {
    it('returns null for empty or null token', async () => {
      const res1 = await extractUserFromToken('');
      const res2 = await extractUserFromToken(null);
      assert.equal(res1, null);
      assert.equal(res2, null);
    });

    it('returns null for invalid/malformed token', async () => {
      const res = await extractUserFromToken('malformed.token.value');
      assert.equal(res, null);
    });

    it('extracts valid user profile from signed token', async () => {
      const user = await db.createUser({
        email: 'token.tester@example.com',
        password: 'ValidPassword123!',
        displayName: 'Token Tester',
      });

      const token = signJwt({ userId: user.id, email: user.email, role: user.role });
      const extracted = await extractUserFromToken(token);

      assert.ok(extracted);
      assert.equal(extracted.id, user.id);
      assert.equal(extracted.email, 'token.tester@example.com');
      assert.equal(extracted.role, 'user');
    });
  });

  describe('Pagination & Query Clamping', () => {
    it('clamps totalPages to at least 1 even on empty result set', async () => {
      const emptyUser = await db.createUser({
        email: 'empty.scanner@example.com',
        password: 'ValidPassword123!',
      });

      const res = await db.getScansByUser(emptyUser.id, { page: 1, limit: 10 });
      assert.equal(res.total, 0);
      assert.equal(res.totalPages, 1);
      assert.deepEqual(res.scans, []);
    });

    it('sanitizes search filter in scans query without throwing', async () => {
      const user = await db.createUser({
        email: 'search.tester@example.com',
        password: 'ValidPassword123!',
      });

      // Special characters like commas and parens that would break PostgREST
      const res = await db.getScansByUser(user.id, { search: 'test,with(parens)' });
      assert.ok(res);
      assert.equal(res.total, 0);
    });
  });
});

