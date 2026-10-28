import path from 'node:path';
import express from 'express';
import cors from 'cors';
import { config } from './config/index.js';
import { requestIdMiddleware } from './middleware/requestId.js';
import { createSecurityHeaders } from './middleware/securityHeaders.js';
import { standardRateLimiter } from './middleware/rateLimiter.js';
import { errorHandler } from './middleware/errorHandler.js';

import healthRoutes from './routes/health.js';
import authRoutes from './routes/auth.js';
import scanRoutes from './routes/scans.js';
import learningRoutes from './routes/learning.js';
import progressRoutes from './routes/progress.js';
import reportRoutes from './routes/reports.js';
import adminRoutes from './routes/admin.js';

const app = express();

// Trust proxy when behind reverse proxy
app.set('trust proxy', 1);

// Security Headers
app.use(createSecurityHeaders());

// CORS configuration
app.use(
  cors({
    origin: config.isProd ? config.frontendOrigin : true,
    credentials: true,
  })
);

// Standard JSON & URL-encoded body parsing with strict size limits
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Request ID tracking
app.use(requestIdMiddleware);

// Static frontend file serving
const publicPath = path.resolve(process.cwd(), 'public');
app.use(express.static(publicPath));

// API Rate Limiting for general endpoints
app.use('/api', standardRateLimiter);

// Route Mounts
app.use('/api', healthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/learning', learningRoutes);
app.use('/api/progress', progressRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/admin', adminRoutes);

// Catch-all 404 for unknown API routes
app.all('/api/*', (req, res) => {
  res.status(404).json({
    error: {
      code: 'NOT_FOUND',
      message: `The requested endpoint ${req.method} ${req.originalUrl} does not exist.`,
    },
  });
});

// Centralized Error Handling Middleware
app.use(errorHandler);

export default app;

