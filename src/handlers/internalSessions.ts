/**
 * Internal Session Endpoints
 *
 * GET  /api/internal/sessions/by-user      — List active refresh tokens for a user
 * POST /api/internal/sessions/:id/revoke   — Revoke a specific refresh token
 *
 * Both gated by `X-CP-Internal-Secret` header (constant-time comparison).
 *
 * Security:
 * - Gated by shared internal secret (NOT JWT — caller is platform-api Worker)
 * - userId is sourced from the signed request body provided by the trusted caller
 *   (platform-api derives userId from the validated JWT sub claim — never from
 *   user-controlled query params at the platform-api boundary)
 * - Revoke validates session belongs to caller's userId before mutating
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { requireInternalSecret } from '../security/internalSecret.js';
import { jsonResponse, jsonError } from '../util/httpJson.js';

// ─── GET /api/internal/sessions/by-user ─────────────────────

async function handleListSessions(request: Request, env: Env): Promise<Response> {
  const userId = request.headers.get('X-CP-User-Id');
  if (!userId) {
    return jsonError('userId is required', 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const sessions = await db.getActiveSessionsByUser(userId);

  return jsonResponse({
    sessions: sessions.map(s => ({
      id: s.id,
      deviceLabel: s.device_label,
      deviceFingerprint: s.device_fingerprint,
      deviceRemembered: s.device_remembered === 1,
      createdAt: s.created_at,
      lastUsedAt: s.last_used_at,
      ipCountry: s.ip,
    })),
  });
}

// ─── POST /api/internal/sessions/:id/revoke ──────────────────

async function handleRevokeSession(
  sessionId: string,
  request: Request,
  env: Env,
): Promise<Response> {
  let body: { userId?: string };
  try {
    body = await request.json() as { userId?: string };
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  const { userId } = body;
  if (!userId || typeof userId !== 'string') {
    return jsonError('userId is required', 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const revoked = await db.revokeSessionById(sessionId, userId);

  if (!revoked) {
    // Either session not found, already revoked, or belongs to a different user
    return jsonError('Session not found or already revoked', 403);
  }

  return jsonResponse({ revoked: true, sessionId });
}

// ─── Unified Handler ─────────────────────────────────────────

/**
 * Route handler for /api/internal/sessions* endpoints.
 * Validates internal secret, then dispatches to method-specific handlers.
 */
export async function handleInternalSessions(request: Request, env: Env): Promise<Response> {
  const denied = requireInternalSecret(request, env);
  if (denied) return denied;

  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === 'GET' && path === '/api/internal/sessions/by-user') {
    return handleListSessions(request, env);
  }

  // POST /api/internal/sessions/:id/revoke
  const revokeMatch = path.match(/^\/api\/internal\/sessions\/([^/]+)\/revoke$/);
  if (method === 'POST' && revokeMatch) {
    return handleRevokeSession(revokeMatch[1], request, env);
  }

  return jsonError('Not found', 404);
}
