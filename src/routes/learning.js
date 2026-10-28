import { Router } from 'express';
import { z } from 'zod';
import { db } from '../services/db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

const scenarioSubmissionSchema = z.object({
  selectedIndicators: z.array(z.string()).default([]),
});

const quizSubmissionSchema = z.object({
  answers: z.record(z.union([z.string(), z.array(z.string())])),
});

// ==========================================
// SCENARIOS
// ==========================================

router.get('/scenarios', async (req, res, next) => {
  try {
    const difficulty = typeof req.query.difficulty === 'string' ? req.query.difficulty : undefined;
    const scenarios = await db.getScenarios({ difficulty, enabledOnly: true });
    res.json({ scenarios });
  } catch (err) {
    next(err);
  }
});

router.get('/scenarios/:id', async (req, res, next) => {
  try {
    const scenario = await db.getScenarioById(req.params.id, false);
    if (!scenario) {
      return res.status(404).json({
        error: {
          code: 'SCENARIO_NOT_FOUND',
          message: 'Educational scenario not found.',
        },
      });
    }
    res.json({ scenario });
  } catch (err) {
    next(err);
  }
});

router.post('/scenarios/:id/submit', requireAuth, async (req, res, next) => {
  try {
    const parseRes = scenarioSubmissionSchema.safeParse(req.body);
    if (!parseRes.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid submission payload format',
        },
      });
    }

    const attempt = await db.submitScenarioAnswer(
      req.params.id,
      req.user.id,
      parseRes.data.selectedIndicators
    );

    res.json({
      message: 'Scenario submission evaluated',
      attempt,
    });
  } catch (err) {
    next(err);
  }
});

// ==========================================
// QUIZZES
// ==========================================

router.get('/quizzes', async (req, res, next) => {
  try {
    const difficulty = typeof req.query.difficulty === 'string' ? req.query.difficulty : undefined;
    const quizzes = await db.getQuizzes({ difficulty, enabledOnly: true });
    res.json({ quizzes });
  } catch (err) {
    next(err);
  }
});

router.get('/quizzes/:id', async (req, res, next) => {
  try {
    const quiz = await db.getQuizDetails(req.params.id);
    if (!quiz) {
      return res.status(404).json({
        error: {
          code: 'QUIZ_NOT_FOUND',
          message: 'Quiz not found.',
        },
      });
    }
    res.json({ quiz });
  } catch (err) {
    next(err);
  }
});

router.post('/quizzes/:id/submit', requireAuth, async (req, res, next) => {
  try {
    const parseRes = quizSubmissionSchema.safeParse(req.body);
    if (!parseRes.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Answers must be formatted as a key-value map',
        },
      });
    }

    const attempt = await db.submitQuizAnswers(
      req.params.id,
      req.user.id,
      parseRes.data.answers
    );

    res.json({
      message: 'Quiz evaluated successfully',
      attempt,
    });
  } catch (err) {
    next(err);
  }
});

// ==========================================
// ATTEMPTS HISTORY
// ==========================================

router.get('/attempts', requireAuth, async (req, res, next) => {
  try {
    const scenarioAttempts = await db.getUserLearningAttempts(req.user.id);
    const quizAttempts = await db.getUserQuizAttempts(req.user.id);

    res.json({
      scenarioAttempts,
      quizAttempts,
    });
  } catch (err) {
    next(err);
  }
});

export default router;

