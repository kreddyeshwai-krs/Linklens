import { Router } from 'express';
import { db } from '../services/db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

router.get('/', requireAuth, async (req, res, next) => {
  try {
    const progress = await db.getUserProgress(req.user.id);
    res.json({ progress });
  } catch (err) {
    next(err);
  }
});

export default router;

