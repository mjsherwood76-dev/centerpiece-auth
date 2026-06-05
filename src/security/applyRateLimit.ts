/**
 * @file applyRateLimit.ts
 * @description Per-route rate-limit middleware for `centerpiece-auth`.
 * Phase 3.12, Session 2.
 *
 * Applies the shared `AUTH_POLICIES` table from
 * `@centerpiece/site-compositor/security` to credential-bearing auth endpoints
 * (/api/login, /api/register, /api/forgot-password, /api/reset-password,
 * /api/switch-tenant, /api/auth/step-up, /oauth/authorize, /oauth/token).
 *
 * Wired EARLY in `worker.ts` — after CORS preflight handling, before route
 * dispatch. Routes with no matching policy (health, JWKS, .well-known,
 * internal service-to-service endpoints, OAuth provider callbacks) pass through
 * untouched.
 *
 * Scope: every AUTH_POLICIES entry is `'ip'` (these are pre-auth surfaces, so
 * no userId/tenantId is resolved yet), so `check` needs no identity context.
 *
 * 429 responses set `Cache-Control: no-store, private` so a blocked response is
 * never cached at the edge or by a browser, which would lock out an IP for the
 * full cache TTL.
 *
 * Fail-open: the shared `RateLimiter` itself allows the request if KV throws —
 * a KV outage never takes down login.
 */

import { RateLimiter, AUTH_POLICIES, matchPolicy } from '@centerpiece/site-compositor/security';
import type { Env } from '../types.js';
import type { Logger } from '../core/logger.js';
import { logAuthEvent } from './auditLog.js';

/**
 * Apply the shared AUTH_POLICIES rate limit to this request.
 *
 * @returns `null` if the request is allowed (caller proceeds to dispatch), or a
 *   `Response` (429) to return immediately if the request is rate-limited.
 */
export async function applyRateLimit(
  request: Request,
  env: Env,
  logger: Logger,
  correlationId: string,
): Promise<Response | null> {
  const policy = matchPolicy(request, AUTH_POLICIES);
  if (!policy) {
    // Unbound endpoint — pass through.
    return null;
  }

  const limiter = new RateLimiter(env.RATE_LIMIT_KV, env.ANALYTICS);
  const result = await limiter.check(request, policy, {});

  if (result.allowed) {
    return null;
  }

  const path = new URL(request.url).pathname;
  logAuthEvent(logger, {
    event: 'rate_limit_hit',
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown',
    route: path,
    userAgent: request.headers.get('User-Agent'),
    correlationId,
    details: { policy: policy.route, retryAfterSeconds: result.retryAfterSeconds },
  });

  return new Response(
    JSON.stringify({ error: 'rate_limited', retryAfter: result.retryAfterSeconds }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(result.retryAfterSeconds),
        'Cache-Control': 'no-store, private',
      },
    },
  );
}
