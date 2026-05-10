/**
 * Impersonation Handler — Internal API
 *
 * POST /api/internal/impersonate — Issue a short-lived JWT for admin impersonation.
 *
 * Called by platform-api via Service Binding when a platform admin
 * wants to impersonate a seller tenant. NOT user-facing.
 *
 * Security:
 * - Gated by X-CP-Internal-Secret (constant-time comparison)
 * - Issues JWT with `impersonatedBy` and `sessionType: 'impersonation'` claims
 * - Short TTL (~5 minutes), no refresh token
 * - Caller must pass their userId, contexts, and reason for audit
 */
import type { Env } from '../types.js';
import { signJwt, buildImpersonationJwtPayload } from '../crypto/jwt.js';
import { ConsoleJsonLogger } from '../core/logger.js';
import { logAuthEvent } from '../security/auditLog.js';
import { constantTimeEqual } from '../security/constantTime.js';

const logger = new ConsoleJsonLogger();

/** Impersonation token TTL: 5 minutes (300 seconds). */
const IMPERSONATION_TTL_SECONDS = 300;

interface ImpersonateRequest {
  userId: string;
  email: string;
  name: string;
  tenantId: string;
  reason: string;
  sessionId: string;
  callerContexts: Record<string, string[]>;
}

export async function handleImpersonate(request: Request, env: Env): Promise<Response> {
  // ── Validate internal secret ──
  const internalSecret = env.INTERNAL_SECRET;
  if (!internalSecret) {
    return jsonResponse({ error: 'Internal endpoint not configured' }, 503);
  }

  const providedSecret = request.headers.get('X-CP-Internal-Secret') || '';
  if (!constantTimeEqual(providedSecret, internalSecret)) {
    return jsonResponse({ error: 'Forbidden' }, 403);
  }

  // ── Parse body ──
  let body: ImpersonateRequest;
  try {
    body = await request.json() as ImpersonateRequest;
  } catch {
    return jsonResponse({ error: 'Invalid request body' }, 400);
  }

  const { userId, email, name, tenantId, reason, sessionId, callerContexts } = body;

  if (!userId || !tenantId || !reason) {
    return jsonResponse({ error: 'Missing required fields: userId, tenantId, reason' }, 400);
  }

  // ── Verify caller has impersonate capability ──
  // The platform-api already checked this, but defense-in-depth: verify platform context exists
  const platformRoles = callerContexts?.platform;
  if (!Array.isArray(platformRoles) || platformRoles.length === 0) {
    return jsonResponse({ error: 'Caller lacks platform context' }, 403);
  }

  // ── Verify target tenant exists ──
  const tenantRow = await env.TENANTS_DB
    .prepare('SELECT id, name FROM tenants WHERE id = ?')
    .bind(tenantId)
    .first<{ id: string; name: string }>();

  if (!tenantRow) {
    return jsonResponse({ error: 'Tenant not found' }, 404);
  }

  // ── Issue impersonation JWT ──
  // The admin gets seller:owner context on the target tenant,
  // plus the impersonatedBy + sessionType claims for audit/denylist.
  const accessToken = await signJwt(
    buildImpersonationJwtPayload({
      userId,
      email,
      name: name || '',
      iss: env.AUTH_DOMAIN,
      tenantId,
      // Preserves existing behaviour: admin's own userId is the audit marker
      // for who initiated the impersonation. (See AUTH-7 follow-up if this
      // ever needs to diverge from `sub`.)
      impersonatedBy: userId,
    }),
    env.JWT_PRIVATE_KEY,
    IMPERSONATION_TTL_SECONDS,
  );

  const correlationId = request.headers.get('X-CP-Request-Id') || crypto.randomUUID();

  logAuthEvent(logger, {
    event: 'impersonation_token_issued',
    ip: request.headers.get('CF-Connecting-IP') || 'internal',
    route: '/api/internal/impersonate',
    correlationId,
    details: {
      adminUserId: userId,
      targetTenantId: tenantId,
      targetTenantName: tenantRow.name,
      reason,
      sessionId,
      ttlSeconds: IMPERSONATION_TTL_SECONDS,
    },
  });

  return jsonResponse({
    accessToken,
    expiresIn: IMPERSONATION_TTL_SECONDS,
  }, 200);
}

// ─── Helpers ────────────────────────────────────────────────

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

