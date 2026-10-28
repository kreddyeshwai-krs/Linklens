import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3000),
  FRONTEND_ORIGIN: z.string().default('http://localhost:3000'),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  SUPABASE_URL: z.string().url().optional().or(z.literal('')),
  SUPABASE_ANON_KEY: z.string().optional().or(z.literal('')),
  SUPABASE_SERVICE_ROLE_KEY: z.string().optional().or(z.literal('')),
  THREAT_INTELLIGENCE_PROVIDER: z.string().optional().or(z.literal('')),
  THREAT_INTELLIGENCE_API_KEY: z.string().optional().or(z.literal('')),
  SCAN_RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000), // 15 mins
  SCAN_RATE_LIMIT_MAX: z.coerce.number().default(30),
  AUTH_RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000),
  AUTH_RATE_LIMIT_MAX: z.coerce.number().default(20),
  JWT_SECRET: z.string().default('linklens_dev_jwt_secret_change_in_production_min32chars'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error('Invalid environment variables:', parsed.error.format());
  process.exit(1);
}

export const config = {
  env: parsed.data.NODE_ENV,
  isProd: parsed.data.NODE_ENV === 'production',
  isDev: parsed.data.NODE_ENV === 'development',
  isTest: parsed.data.NODE_ENV === 'test',
  port: parsed.data.PORT,
  frontendOrigin: parsed.data.FRONTEND_ORIGIN,
  logLevel: parsed.data.LOG_LEVEL,
  supabase: {
    url: parsed.data.SUPABASE_URL || null,
    anonKey: parsed.data.SUPABASE_ANON_KEY || null,
    serviceRoleKey: parsed.data.SUPABASE_SERVICE_ROLE_KEY || null,
    isConfigured: Boolean(parsed.data.SUPABASE_URL && (parsed.data.SUPABASE_ANON_KEY || parsed.data.SUPABASE_SERVICE_ROLE_KEY)),
  },
  threatIntel: {
    provider: parsed.data.THREAT_INTELLIGENCE_PROVIDER || null,
    apiKey: parsed.data.THREAT_INTELLIGENCE_API_KEY || null,
    enabled: Boolean(parsed.data.THREAT_INTELLIGENCE_PROVIDER && parsed.data.THREAT_INTELLIGENCE_API_KEY),
  },
  rateLimits: {
    scanWindowMs: parsed.data.SCAN_RATE_LIMIT_WINDOW_MS,
    scanMax: parsed.data.SCAN_RATE_LIMIT_MAX,
    authWindowMs: parsed.data.AUTH_RATE_LIMIT_WINDOW_MS,
    authMax: parsed.data.AUTH_RATE_LIMIT_MAX,
  },
  jwtSecret: parsed.data.JWT_SECRET,
};

