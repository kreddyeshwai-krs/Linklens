import { Router } from 'express';
import { config } from '../config/index.js';
import { RULESET_VERSION } from '../engine/risk-scoring.js';
import { isSupabaseActive } from '../services/supabase.js';

const router = Router();

router.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    environment: config.env,
  });
});

router.get('/config', (req, res) => {
  res.json({
    appName: 'Link Lens',
    version: '1.0.0',
    rulesetVersion: RULESET_VERSION,
    supabaseConfigured: isSupabaseActive(),
    threatIntelEnabled: config.threatIntel.enabled,
    threatIntelProvider: config.threatIntel.provider,
    rateLimits: {
      scanWindowMinutes: Math.round(config.rateLimits.scanWindowMs / 60000),
      scanMax: config.rateLimits.scanMax,
    },
  });
});

export default router;

