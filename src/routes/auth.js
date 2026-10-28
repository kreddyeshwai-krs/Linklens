import { Router } from 'express';
import { z } from 'zod';
import { db } from '../services/db.js';
import { signJwt } from '../utils/jwt.js';
import { requireAuth } from '../middleware/auth.js';
import { authRateLimiter } from '../middleware/rateLimiter.js';

const router = Router();

const signupSchema = z.object({
  email: z.string().email('Please provide a valid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters long'),
  displayName: z.string().min(2).max(50).optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const preferenceSchema = z.object({
  displayName: z.string().min(2).max(50).optional(),
  themePreference: z.enum(['dark', 'light', 'system']).optional(),
  role: z.string().optional(), // Used to verify rejection of client role changes
});

router.post('/signup', authRateLimiter, async (req, res, next) => {
  try {
    const parseRes = signupSchema.safeParse(req.body);
    if (!parseRes.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: parseRes.error.errors[0]?.message || 'Invalid input data',
        },
      });
    }

    const { email, password, displayName } = parseRes.data;
    // Users ALWAYS default to 'user' role; client cannot pass 'admin'
    const user = await db.createUser({
      email,
      password,
      displayName,
      role: 'user',
    });

    const token = signJwt({ userId: user.id, email: user.email, role: user.role });

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        role: user.role,
        themePreference: user.theme_preference,
      },
    });
  } catch (err) {
    const msg = err.message ? err.message.toLowerCase() : '';
    if (msg.includes('already exists') || msg.includes('already been registered')) {
      return res.status(409).json({
        error: {
          code: 'USER_EXISTS',
          message: 'An account with this email address already exists.',
        },
      });
    }
    next(err);
  }
});

router.post('/login', authRateLimiter, async (req, res, next) => {
  try {
    const parseRes = loginSchema.safeParse(req.body);
    if (!parseRes.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Valid email and password are required',
        },
      });
    }

    const { email, password } = parseRes.data;
    const user = await db.authenticateUser(email, password);

    if (!user) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Incorrect email or password.',
        },
      });
    }

    const token = signJwt({ userId: user.id, email: user.email, role: user.role });

    res.json({
      message: 'Authenticated successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        role: user.role,
        themePreference: user.theme_preference,
      },
    });
  } catch (err) {
    next(err);
  }
});

router.get('/me', requireAuth, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      displayName: req.user.display_name,
      role: req.user.role,
      themePreference: req.user.theme_preference,
      createdAt: req.user.created_at,
    },
  });
});

router.patch('/preferences', requireAuth, async (req, res, next) => {
  try {
    const parseRes = preferenceSchema.safeParse(req.body);
    if (!parseRes.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid preferences payload',
        },
      });
    }

    // Attempting to elevate role as non-admin must fail
    if (parseRes.data.role && req.user.role !== 'admin') {
      return res.status(403).json({
        error: {
          code: 'ROLE_ELEVATION_DENIED',
          message: 'Permission denied: Users cannot elevate their own role.',
        },
      });
    }

    const updated = await db.updateProfile(
      req.user.id,
      {
        displayName: parseRes.data.displayName,
        themePreference: parseRes.data.themePreference,
        role: parseRes.data.role,
      },
      req.user.role === 'admin'
    );

    res.json({
      message: 'Preferences updated',
      user: {
        id: updated.id,
        displayName: updated.display_name,
        role: updated.role,
        themePreference: updated.theme_preference,
      },
    });
  } catch (err) {
    next(err);
  }
});

export default router;

