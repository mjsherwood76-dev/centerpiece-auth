/**
 * Internal-secret gate for service-to-service endpoints.
 *
 * Centralizes the X-CP-Internal-Secret handshake used by every internal
 * endpoint (impersonate, internalUsers, internalCustomers,
 * internalMemberships). Constant-time comparison prevents timing attacks.
 *
 * Pair with `centerpiece-platform-api/src/util/internalSecret.ts` on the
 * caller side — both must agree on header name + comparison semantics.
 */
import type { Env } from '../types.js';
import { constantTimeEqual } from './constantTime.js';

/**
 * Validate the `X-CP-Internal-Secret` header against `env.INTERNAL_SECRET`.
 *
 * Returns a Response (503 if unconfigured, 403 if mismatched) on failure,
 * or null on success. Callers do:
 *
 *   const denied = requireInternalSecret(request, env);
 *   if (denied) return denied;
 */
export function requireInternalSecret(request: Request, env: Env): Response | null {
  const internalSecret = env.INTERNAL_SECRET;
  if (!internalSecret) {
    return new Response(JSON.stringify({ error: 'Internal endpoint not configured' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }

  const provided = request.headers.get('X-CP-Internal-Secret') ?? '';
  if (!constantTimeEqual(provided, internalSecret)) {
    return new Response(JSON.stringify({ error: 'Forbidden' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }

  return null;
}
