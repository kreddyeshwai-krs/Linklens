import { config } from '../config/index.js';

export function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || (err.name === 'ValidationError' ? 400 : 500);
  const errorCode = err.code || 'INTERNAL_SERVER_ERROR';

  // Do not log secrets or sensitive headers
  if (config.logLevel === 'debug' || statusCode === 500) {
    // eslint-disable-next-line no-console
    console.error(`[${req.id || 'NO_ID'}] ${err.name}: ${err.message}`, {
      path: req.originalUrl,
      method: req.method,
      stack: config.isDev ? err.stack : undefined,
    });
  }

  // Never expose raw stack traces in production responses
  res.status(statusCode).json({
    error: {
      code: errorCode,
      message: err.message || 'An unexpected error occurred.',
      details: err.details || null,
      requestId: req.id,
    },
  });
}

