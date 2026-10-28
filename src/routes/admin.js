import { Router } from 'express';
import { z } from 'zod';
import { db } from '../services/db.js';
import { requireAuth } from '../middleware/auth.js';
import { requireAdmin } from '../middleware/roleCheck.js';

const router = Router();

// Strict authorization guard on all admin routes
router.use(requireAuth, requireAdmin);

const toggleSchema = z.object({
  enabled: z.boolean(),
});

router.get('/overview', async (req, res, next) => {
  try {
    const overview = await db.getAdminOverview();
    res.json({ overview });
  } catch (err) {
    next(err);
  }
});

router.get('/scans', async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));

    const result = await db.getAdminScans({ page, limit });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.patch('/scenarios/:id', async (req, res, next) => {
  try {
    const parseRes = toggleSchema.safeParse(req.body);
    if (!parseRes.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Enabled boolean property is required',
        },
      });
    }

    const updated = await db.toggleScenario(
      req.params.id,
      parseRes.data.enabled,
      req.user.id
    );

    res.json({
      message: `Scenario ${parseRes.data.enabled ? 'activated' : 'deactivated'}`,
      scenario: updated,
    });
  } catch (err) {
    next(err);
  }
});

router.patch('/quizzes/:id', async (req, res, next) => {
  try {
    const parseRes = toggleSchema.safeParse(req.body);
    if (!parseRes.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Enabled boolean property is required',
        },
      });
    }

    const updated = await db.toggleQuiz(
      req.params.id,
      parseRes.data.enabled,
      req.user.id
    );

    res.json({
      message: `Quiz ${parseRes.data.enabled ? 'activated' : 'deactivated'}`,
      quiz: updated,
    });
  } catch (err) {
    next(err);
  }
});

router.get('/audit-logs', async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));

    const result = await db.getAdminAuditLogs({ page, limit });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;

