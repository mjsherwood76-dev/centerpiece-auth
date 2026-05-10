/**
 * Switch Tenant Handler
 *
 * POST /api/switch-tenant — Re-issue a JWT scoped to a different tenant
 *
 * Auth: Bearer JWT required (current admin access token).
 * Body: { tenantId: string }
 *
 * Flow:
 * 1. Verify JWT (signature + expiry)
 * 2. If requested tenant === current primaryTenantId → no-op shortcut (return current token)
 * 3. Platform admin bypass: skip membership check, verify tenant exists + active in TENANTS_DB
 * 4. Regular user: verify active non-customer membership on target tenant
 * 5. Rebuild JWT with new primaryTenantId and recomputed contexts
 * 6. Return new access_token
 *
 * Security:
 * - Only works with aud: 'admin' JWTs
 * - Membership verified server-side before issuing
 * - Platform admin can scope to any active tenant
 * - Does not extend session (standard TTL applies)
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { verifyJwt, signJwt, buildAdminJwtPayload } from '../crypto/jwt.js';

export async function handleSwitchTenant(request: Request, env: Env): Promise<Response> {
  // ── Extract and verify JWT ──
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonError('Unauthorized', 401);
  }

  const token = authHeader.slice(7);
  const payload = await verifyJwt(token, env.JWT_PUBLIC_KEY);

  if (!payload) {
    return jsonError('Unauthorized', 401);
  }

  // Only admin JWTs can switch tenants
  if (payload.aud !== 'admin') {
    return jsonError('Unauthorized', 401);
  }

  // ── Parse body ──
  let requestedTenantId: string;
  try {
    const body = await request.json() as Record<string, unknown>;
    requestedTenantId = typeof body.tenantId === 'string' ? body.tenantId.trim() : '';
  } catch {
    return jsonError('tenantId is required', 400);
  }

  if (!requestedTenantId) {
    return jsonError('tenantId is required', 400);
  }

  // ── No-op shortcut: same tenant ──
  if (requestedTenantId === payload.primaryTenantId) {
    const remainingTtl = payload.exp - Math.floor(Date.now() / 1000);
    return new Response(
      JSON.stringify({
        access_token: token,
        token_type: 'Bearer',
        expires_in: remainingTtl > 0 ? remainingTtl : 0,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      },
    );
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Determine if platform admin ──
  const isPlatformOwner = payload.contexts?.['platform'] !== undefined;

  if (isPlatformOwner) {
    // Platform admin bypass: verify tenant exists and is active in TENANTS_DB
    const tenantRow = await env.TENANTS_DB
      .prepare('SELECT id FROM tenants WHERE id = ? AND status = ?')
      .bind(requestedTenantId, 'active')
      .first<{ id: string }>();

    if (!tenantRow) {
      return jsonError('Tenant not found or inactive', 404);
    }
  } else {
    // Regular user: verify active non-customer membership on target tenant
    const membershipCheck = await env.AUTH_DB
      .prepare(
        `SELECT context, sub_role FROM tenant_memberships
         WHERE user_id = ? AND tenant_id = ? AND context != 'customer' AND status = 'active'`
      )
      .bind(payload.sub, requestedTenantId)
      .all<{ context: string; sub_role: string }>();

    if (!membershipCheck.results || membershipCheck.results.length === 0) {
      return jsonError('No membership on this tenant', 403);
    }
  }

  // ── Build new JWT ──
  const allMemberships = await db.getAdminMemberships(payload.sub);
  const contexts: Record<string, string[]> = {};

  // Include contexts from the target tenant
  const tenantMemberships = allMemberships.filter(m => m.tenant_id === requestedTenantId);
  for (const m of tenantMemberships) {
    if (!contexts[m.context]) contexts[m.context] = [];
    if (m.sub_role && !contexts[m.context].includes(m.sub_role)) {
      contexts[m.context].push(m.sub_role);
    }
  }

  // Include platform contexts if user has __platform__ memberships
  const platformMemberships = allMemberships.filter(
    m => m.tenant_id === '__platform__' && m.context === 'platform',
  );
  if (platformMemberships.length > 0) {
    contexts['platform'] = [];
    for (const m of platformMemberships) {
      if (m.sub_role && !contexts['platform'].includes(m.sub_role)) {
        contexts['platform'].push(m.sub_role);
      }
    }
  }

  const ttlSeconds = parseInt(env.ACCESS_TOKEN_TTL_SECONDS || '900', 10);

  // Look up user for name/email (needed for JWT claims)
  const user = await db.getUserById(payload.sub);
  if (!user) {
    return jsonError('Unauthorized', 401);
  }

  const accessToken = await signJwt(
    buildAdminJwtPayload({
      userId: user.id,
      email: user.email,
      name: user.name || '',
      iss: env.AUTH_DOMAIN,
      contexts,
      primaryTenantId: requestedTenantId,
    }),
    env.JWT_PRIVATE_KEY,
    ttlSeconds,
  );

  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ttlSeconds,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    },
  );
}

// ─── Helpers ────────────────────────────────────────────────

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}
