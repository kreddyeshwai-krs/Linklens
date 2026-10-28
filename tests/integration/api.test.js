import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../../src/app.js';
import { db } from '../../src/services/db.js';

describe('Link Lens API Integration Tests', () => {
  let userAToken = '';
  let userBToken = '';
  let adminToken = '';
  let userAId = '';
  let userBId = '';
  let userAScanId = '';

  before(async () => {
    await db.resetForTesting();

    // Create User A
    const resA = await request(app)
      .post('/api/auth/signup')
      .send({
        email: 'usera@example.org',
        password: 'Password123!',
        displayName: 'Analyst A',
      });
    assert.equal(resA.status, 201);
    userAToken = resA.body.token;
    userAId = resA.body.user.id;

    // Create User B
    const resB = await request(app)
      .post('/api/auth/signup')
      .send({
        email: 'userb@example.org',
        password: 'Password123!',
        displayName: 'Analyst B',
      });
    assert.equal(resB.status, 201);
    userBToken = resB.body.token;
    userBId = resB.body.user.id;

    // Create Admin user via internal provisioning
    const adminUser = await db.createUser({
      email: 'admin@example.org',
      password: 'AdminPassword123!',
      displayName: 'System Admin',
      role: 'admin',
    });
    const adminLogin = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'admin@example.org',
        password: 'AdminPassword123!',
      });
    adminToken = adminLogin.body.token;
  });

  describe('Health & Public Config', () => {
    it('returns 200 on /api/health', async () => {
      const res = await request(app).get('/api/health');
      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'ok');
    });

    it('returns 200 and safe metadata on /api/config', async () => {
      const res = await request(app).get('/api/config');
      assert.equal(res.status, 200);
      assert.equal(res.body.appName, 'Link Lens');
      assert.ok(res.body.rulesetVersion);
    });
  });

  describe('Authentication & Privilege Escalation Defenses', () => {
    it('rejects access to protected routes without a token', async () => {
      const res = await request(app).get('/api/auth/me');
      assert.equal(res.status, 401);
      assert.equal(res.body.error.code, 'UNAUTHORIZED');
    });

    it('prevents normal user from elevating role to admin', async () => {
      const res = await request(app)
        .patch('/api/auth/preferences')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          displayName: 'Hacker Attempt',
          role: 'admin',
        });
      assert.equal(res.status, 403);
      assert.equal(res.body.error.code, 'ROLE_ELEVATION_DENIED');
    });

    it('blocks normal user from admin endpoints', async () => {
      const res = await request(app)
        .get('/api/admin/overview')
        .set('Authorization', `Bearer ${userAToken}`);
      assert.equal(res.status, 403);
      assert.equal(res.body.error.code, 'FORBIDDEN');
    });

    it('allows verified admin to access admin overview', async () => {
      const res = await request(app)
        .get('/api/admin/overview')
        .set('Authorization', `Bearer ${adminToken}`);
      assert.equal(res.status, 200);
      assert.ok(res.body.overview.totalUsers >= 2);
    });
  });

  describe('Scans & User Data Isolation', () => {
    it('allows User A to initiate a URL scan and persists it', async () => {
      const res = await request(app)
        .post('/api/scans')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          url: 'https://security-update-chase.example.org/login?redirect=https://evil.example.net',
        });
      assert.equal(res.status, 201);
      assert.ok(res.body.scan.id);
      assert.ok(res.body.scan.risk_score > 0);
      userAScanId = res.body.scan.id;
    });

    it('allows User A to view their own scan in history', async () => {
      const res = await request(app)
        .get('/api/scans')
        .set('Authorization', `Bearer ${userAToken}`);
      assert.equal(res.status, 200);
      assert.equal(res.body.total, 1);
      assert.equal(res.body.scans[0].id, userAScanId);
    });

    it('strictly isolates scan data: User B cannot access User A scan details', async () => {
      const res = await request(app)
        .get(`/api/scans/${userAScanId}`)
        .set('Authorization', `Bearer ${userBToken}`);
      assert.equal(res.status, 404);
      assert.equal(res.body.error.code, 'SCAN_NOT_FOUND');
    });

    it('strictly isolates deletion: User B cannot delete User A scan', async () => {
      const res = await request(app)
        .delete(`/api/scans/${userAScanId}`)
        .set('Authorization', `Bearer ${userBToken}`);
      assert.equal(res.status, 404);
    });

    it('allows User A to delete their own scan', async () => {
      const res = await request(app)
        .delete(`/api/scans/${userAScanId}`)
        .set('Authorization', `Bearer ${userAToken}`);
      assert.equal(res.status, 200);

      // Verify deletion
      const checkRes = await request(app)
        .get(`/api/scans/${userAScanId}`)
        .set('Authorization', `Bearer ${userAToken}`);
      assert.equal(checkRes.status, 404);
    });
  });

  describe('Learning Scenarios & Server-Calculated Quizzes', () => {
    it('publicly returns scenarios without exposing authoritative answers', async () => {
      const res = await request(app).get('/api/learning/scenarios');
      assert.equal(res.status, 200);
      assert.ok(res.body.scenarios.length > 0);
      // Verify correct_indicators is NOT exposed
      for (const s of res.body.scenarios) {
        assert.equal(s.correct_indicators, undefined);
      }
    });

    it('evaluates scenario answers server-side with educational feedback', async () => {
      const scenariosRes = await request(app).get('/api/learning/scenarios');
      const firstScenario = scenariosRes.body.scenarios[0];

      const res = await request(app)
        .post(`/api/learning/scenarios/${firstScenario.id}/submit`)
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          selectedIndicators: ['secure-chase.com', 'account-verification-auth', 'example.com'],
        });
      assert.equal(res.status, 200);
      assert.ok(res.body.attempt.score >= 70);
      assert.equal(res.body.attempt.correct, true);
      assert.ok(res.body.attempt.feedback.saferAction);
    });

    it('publicly returns quiz questions without exposing correct_answer', async () => {
      const quizzesRes = await request(app).get('/api/learning/quizzes');
      assert.equal(quizzesRes.status, 200);
      const quizId = quizzesRes.body.quizzes[0].id;

      const detailRes = await request(app).get(`/api/learning/quizzes/${quizId}`);
      assert.equal(detailRes.status, 200);
      assert.ok(detailRes.body.quiz.questions.length > 0);

      for (const q of detailRes.body.quiz.questions) {
        assert.equal(q.correct_answer, undefined);
      }
    });

    it('calculates quiz score strictly on the server', async () => {
      const quizzesRes = await request(app).get('/api/learning/quizzes');
      const quizId = quizzesRes.body.quizzes[0].id;

      // Submit correct answer for question 1 (opt3), correct for question 2 (opt1, opt3), correct for q3 (opt2)
      const res = await request(app)
        .post(`/api/learning/quizzes/${quizId}/submit`)
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          answers: {
            '20000000-0000-0000-0000-000000000001': 'opt3',
            '20000000-0000-0000-0000-000000000002': ['opt1', 'opt3'],
            '20000000-0000-0000-0000-000000000003': 'opt2',
          },
        });
      assert.equal(res.status, 200);
      assert.equal(res.body.attempt.score, 100);
      assert.ok(res.body.attempt.total_points > 0);
    });

    it('tracks user progress and badges after activity', async () => {
      const res = await request(app)
        .get('/api/progress')
        .set('Authorization', `Bearer ${userAToken}`);
      assert.equal(res.status, 200);
      assert.ok(res.body.progress.completedScenarios >= 1);
      assert.ok(res.body.progress.passedQuizzes >= 1);
      assert.ok(res.body.progress.badges.length >= 1);
    });
  });
});

