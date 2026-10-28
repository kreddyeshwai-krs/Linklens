import { createClient } from '@supabase/supabase-js';
import { config } from '../config/index.js';

let supabaseClient = null;
let supabaseAdminClient = null;

if (config.supabase.isConfigured) {
  if (config.supabase.anonKey) {
    supabaseClient = createClient(config.supabase.url, config.supabase.anonKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });
  }

  if (config.supabase.serviceRoleKey) {
    supabaseAdminClient = createClient(config.supabase.url, config.supabase.serviceRoleKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });
  }
}

/**
 * Returns the public / anon Supabase client.
 * Falls back to admin client if only service role key is configured.
 */
export function getSupabase() {
  return supabaseClient || supabaseAdminClient;
}

/**
 * Returns the privileged server-side Supabase client (service role).
 * Falls back to public client if service role is not provided.
 */
export function getSupabaseAdmin() {
  return supabaseAdminClient || supabaseClient;
}

/**
 * Check if service role key client is available for administrative operations
 */
export function hasServiceRole() {
  return Boolean(supabaseAdminClient);
}

/**
 * Check if active live connection to Supabase is enabled
 */
export function isSupabaseActive() {
  return Boolean(supabaseAdminClient || supabaseClient);
}
