import { Router } from 'express';
import { z } from 'zod';
import { orchestrateScan } from '../engine/scan-orchestrator.js';
import { db } from '../services/db.js';
import { requireAuth } from '../middleware/auth.js';
import { scanRateLimiter } from '../middleware/rateLimiter.js';

const router = Router();

const scanRequestSchema = z.object({
  url: z.string().min(1, 'URL is required').max(2048),
  analysisMode: z.enum(['real', 'simulation']).optional().default('real'),
});

router.post('/', requireAuth, scanRateLimiter, async (req, res, next) => {
  try {
    const parseRes = scanRequestSchema.safeParse(req.body);
    if (!parseRes.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: parseRes.error.errors[0]?.message || 'Invalid scan request',
        },
      });
    }

    const { url, analysisMode } = parseRes.data;

    // Run modular URL analysis engine
    const scanResult = await orchestrateScan(url);
    scanResult.analysis_mode = analysisMode;

    // Persist scan result to database under authenticated user
    const persisted = await db.createScan({
      ...scanResult,
      user_id: req.user.id,
    });

    res.status(201).json({
      message: 'URL analyzed successfully',
      scan: {
        ...persisted,
        positive_indicators: scanResult.positive_indicators,
        limitations: scanResult.limitations,
        recommended_next_steps: scanResult.recommended_next_steps,
      },
    });
  } catch (err) {
    next(err);
  }
});

router.get('/', requireAuth, async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));
    const search = typeof req.query.search === 'string' ? req.query.search : '';
    const riskCategory = typeof req.query.riskCategory === 'string' ? req.query.riskCategory : '';

    const results = await db.getScansByUser(req.user.id, {
      page,
      limit,
      search,
      riskCategory,
    });

    res.json(results);
  } catch (err) {
    next(err);
  }
});

router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const scan = await db.getScanById(req.params.id, req.user.id, isAdmin);

    if (!scan) {
      return res.status(404).json({
        error: {
          code: 'SCAN_NOT_FOUND',
          message: 'Scan record was not found or access is denied.',
        },
      });
    }

    res.json({ scan });
  } catch (err) {
    next(err);
  }
});

router.delete('/:id', requireAuth, async (req, res, next) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const deleted = await db.deleteScan(req.params.id, req.user.id, isAdmin);

    if (!deleted) {
      return res.status(404).json({
        error: {
          code: 'SCAN_NOT_FOUND',
          message: 'Scan not found or permission denied.',
        },
      });
    }

    res.json({
      message: 'Scan deleted successfully',
      scanId: req.params.id,
    });
  } catch (err) {
    next(err);
  }
});

router.delete('/', requireAuth, async (req, res, next) => {
  try {
    await db.clearUserScans(req.user.id);
    res.json({
      message: 'All user scan records have been cleared.',
    });
  } catch (err) {
    next(err);
  }
});

export default router;

