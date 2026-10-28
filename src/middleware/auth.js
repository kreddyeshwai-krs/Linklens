import { verifyJwt } from '../utils/jwt.js';
import { db } from '../services/db.js';
import { getSupabaseAdmin, isSupabaseActive } from '../services/supabase.js';

/**
 * Extracts and verifies the authenticated user from a Bearer token.
 * Supports both Supabase Auth JWTs (when Supabase is configured)
 * and locally signed JWTs.
 */
export async function extractUserFromToken(token) {
  if (!token) return null;

  let userId = null;

  // 1. Check if token is a valid Supabase Auth token
  if (isSupabaseActive()) {
    try {
      const admin = getSupabaseAdmin();
      if (admin?.auth) {
        const { data, error } = await admin.auth.getUser(token);
        if (!error && data?.user?.id) {
          userId = data.user.id;
        }
      }
    } catch (e) {
      // Non-Supabase or malformed token format, proceed to local JWT check
    }
  }

  // 2. If not verified by Supabase, verify with local JWT verifier
  if (!userId) {
    try {
      const payload = verifyJwt(token);
      if (payload && payload.userId) {
        userId = payload.userId;
      }
    } catch (e) {
      // Invalid local token
    }
  }

  if (!userId) return null;

  const profile = await db.getProfileById(userId);
  return profile || null;
}

export async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required. Missing or malformed Bearer token.',
        },
      });
    }

    const token = authHeader.substring(7).trim();
    const user = await extractUserFromToken(token);

    if (!user) {
      return res.status(401).json({
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired session token.',
        },
      });
    }

    // Attach verified user profile to request object
    req.user = user;
    next();
  } catch (err) {
    return res.status(500).json({
      error: {
        code: 'AUTH_VERIFICATION_ERROR',
        message: 'Internal error occurred during token verification.',
      },
    });
  }
}

export async function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    return next();
  }

  const token = authHeader.substring(7).trim();
  try {
    req.user = await extractUserFromToken(token);
  } catch (e) {
    req.user = null;
  }
  next();
}
