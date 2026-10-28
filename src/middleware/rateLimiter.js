import rateLimit from 'express-rate-limit';
import { config } from '../config/index.js';

export const standardRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests from this client. Please retry later.',
    },
  },
});

export const scanRateLimiter = rateLimit({
  windowMs: config.rateLimits.scanWindowMs,
  max: config.rateLimits.scanMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: {
      code: 'SCAN_RATE_LIMIT_EXCEEDED',
      message: `Scan rate limit exceeded. You may initiate up to ${config.rateLimits.scanMax} scans per 15 minutes.`,
    },
  },
});

export const authRateLimiter = rateLimit({
  windowMs: config.rateLimits.authWindowMs,
  max: config.rateLimits.authMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: {
      code: 'AUTH_RATE_LIMIT_EXCEEDED',
      message: 'Too many authentication attempts. Please wait before retrying.',
    },
  },
});

