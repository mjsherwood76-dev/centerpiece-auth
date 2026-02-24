/**
 * Rate Limiting via KV Counters
 *
 * Per-IP rate limits using KV counters (not D1 — KV is faster for
 * hot-path writes and avoids D1 write contention).
 *
 * Key pattern: `ratelimit:{ip}:{route}:{window}`
 * Default: 10 attempts per 15-minute window per IP per route.
 *
 * Also supports per-email throttle on login/forgot-password
 * (to be wired per endpoint as needed).
 */
import type { Env } from '../types.js';

/** Maximum attempts per window. Higher in non-production for integration tests. */
const MAX_ATTEMPTS_PRODUCTION = 10;
const MAX_ATTEMPTS_NON_PRODUCTION = 200;
/** Window size in seconds (15 minutes). */
const WINDOW_SECONDS = 15 * 60;

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

/**
 * Check rate limit for a given IP and route.
 *
 * Uses TENANT_CONFIGS KV for storage (it's the only general-purpose
 * KV binding available; rate limit keys use a distinct prefix to avoid
 * collisions with tenant config data).
 *
 * @param ip - Client IP address
 * @param route - Request path (e.g., '/api/login')
 * @param env - Worker environment
 * @returns Whether the request is allowed
 */
export async function checkRateLimit(
  ip: string,
  route: string,
  env: Env
): Promise<RateLimitResult> {
  const maxAttempts = env.ENVIRONMENT === 'production' ? MAX_ATTEMPTS_PRODUCTION : MAX_ATTEMPTS_NON_PRODUCTION;

  // Compute the window key (floor to nearest window boundary)
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / WINDOW_SECONDS) * WINDOW_SECONDS;
  const key = `ratelimit:${sanitizeKey(ip)}:${sanitizeKey(route)}:${windowStart}`;

  try {
    // Read current count
    const current = await env.TENANT_CONFIGS.get(key, 'text');
    const count = current ? parseInt(current, 10) : 0;

    if (count >= maxAttempts) {
      const windowEnd = windowStart + WINDOW_SECONDS;
      const retryAfter = Math.max(1, windowEnd - now);
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: retryAfter,
      };
    }

    // Increment counter (non-atomic — acceptable for rate limiting)
    const newCount = count + 1;
    const ttlSeconds = WINDOW_SECONDS + 60; // Extra minute buffer for cleanup
    await env.TENANT_CONFIGS.put(key, String(newCount), {
      expirationTtl: ttlSeconds,
    });

    return {
      allowed: true,
      remaining: maxAttempts - newCount,
      retryAfterSeconds: 0,
    };
  } catch (err) {
    // If KV fails, allow the request (fail open for availability)
    console.error('Rate limit check failed:', err);
    return {
      allowed: true,
      remaining: maxAttempts,
      retryAfterSeconds: 0,
    };
  }
}

/**
 * Sanitize a key component to prevent KV key injection.
 */
function sanitizeKey(value: string): string {
  return value.replace(/[^a-zA-Z0-9._:/-]/g, '_').substring(0, 100);
}
