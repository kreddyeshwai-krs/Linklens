/**
 * Server-side Role Check Middleware
 * Enforces administrator privileges. Never trusts client-supplied headers or body fields.
 */
export function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required before checking administrator privileges.',
      },
    });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({
      error: {
        code: 'FORBIDDEN',
        message: 'Access denied: Administrator privileges required for this endpoint.',
      },
    });
  }

  next();
}

