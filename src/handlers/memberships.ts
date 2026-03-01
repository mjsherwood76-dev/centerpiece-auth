/**
 * Memberships Handler
 *
 * GET /api/memberships — Returns the authenticated user's tenant memberships
 *
 * Auth: Bearer JWT required. Reads `sub` claim for user ID.
 * Used by the admin SPA to display tenant picker and role context.
 *
 * Response: { memberships: [{ tenantId, role, status }] }
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { verifyJwt } from '../crypto/jwt.js';

/**
 * Handle GET /api/memberships
 *
 * Requires a valid JWT in the Authorization header.
 * Returns all memberships for the authenticated user.
 */
export async function handleMemberships(request: Request, env: Env): Promise<Response> {
  // ── Extract and verify JWT ──
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonError('Missing or invalid Authorization header', 401);
  }

  const token = authHeader.slice(7);
  const payload = await verifyJwt(token, env.JWT_PUBLIC_KEY);

  if (!payload) {
    return jsonError('Invalid or expired token', 401);
  }

  // ── Query memberships ──
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const memberships = await db.getAllMemberships(payload.sub);

  // ── Format response ──
  const formattedMemberships = memberships.map(m => ({
    tenantId: m.tenant_id,
    role: m.role,
    status: m.status,
  }));

  return new Response(
    JSON.stringify({ memberships: formattedMemberships }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    }
  );
}

// ─── Helpers ────────────────────────────────────────────────

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}
