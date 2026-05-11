/**
 * Internal User Lookup Endpoint
 *
 * GET /api/internal/users/by-email?email=X — Look up a user by email.
 * Gated by `X-CP-Internal-Secret` header (constant-time comparison).
 *
 * This is NOT a user-facing endpoint. It is called by the platform-api
 * Worker during team management to resolve email → userId.
 *
 * Security:
 * - Gated by shared internal secret (NOT JWT — caller is a Worker, not a browser)
 * - Constant-time comparison prevents timing attacks
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { requireInternalSecret } from '../security/internalSecret.js';
import { jsonResponse } from '../util/httpJson.js';

// ─── Handler ────────────────────────────────────────────────

/**
 * Handle GET /api/internal/users/by-email?email=X
 *
 * Looks up a user by email address.
 * Gated by X-CP-Internal-Secret header.
 *
 * Response: 200 { userId, email, name } or 404 { error: 'User not found' }
 */
export async function handleInternalUserLookup(request: Request, env: Env): Promise<Response> {
  // ── Verify internal secret ──
  const denied = requireInternalSecret(request, env);
  if (denied) return denied;

  // ── Parse query parameter ──
  const url = new URL(request.url);
  const email = url.searchParams.get('email')?.trim();
  if (!email) {
    return jsonResponse({ error: 'email query parameter is required' }, 400);
  }

  // ── Look up user ──
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const user = await db.getUserByEmailPublic(email);
  if (!user) {
    return jsonResponse({ error: 'User not found' }, 404);
  }

  return jsonResponse({
    userId: user.id,
    email: user.email,
    name: user.name,
  }, 200);
}
