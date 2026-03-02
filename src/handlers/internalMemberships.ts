/**
 * Internal Membership Creation Endpoint
 *
 * POST /api/internal/memberships — Creates memberships with specified roles.
 * Gated by `X-CP-Internal-Secret` header (constant-time comparison).
 *
 * This is NOT a user-facing endpoint. It is called by the runtime Worker
 * during tenant onboarding to create seller memberships.
 *
 * Security:
 * - Gated by shared internal secret (NOT JWT — caller is a Worker, not a browser)
 * - Constant-time comparison prevents timing attacks
 * - NEVER allows `platform_admin` role creation
 *
 * Phase 2.5, Session 3.
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';

// ─── Types ──────────────────────────────────────────────────

interface CreateMembershipRequest {
  userId: string;
  tenantId: string;
  role: 'seller' | 'supplier';
}

// ─── Helpers ────────────────────────────────────────────────

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Uses byte-by-byte XOR to ensure comparison time is independent of match position.
 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// ─── Blocked roles ──────────────────────────────────────────

/** Roles that can NEVER be created via this internal endpoint. */
const BLOCKED_ROLES = new Set(['platform_admin', 'customer']);

/** Roles allowed for creation via this endpoint. */
const ALLOWED_ROLES = new Set(['seller', 'supplier']);

// ─── Handler ────────────────────────────────────────────────

/**
 * Handle POST /api/internal/memberships
 *
 * Creates a tenant membership for a user with the specified role.
 * Gated by X-CP-Internal-Secret header.
 *
 * Request body: { userId: string, tenantId: string, role: 'seller' | 'supplier' }
 * Response: 201 { membershipId, userId, tenantId, role }
 * Errors: 403 (bad secret / blocked role), 400 (bad input), 409 (exists)
 */
export async function handleInternalMemberships(request: Request, env: Env): Promise<Response> {
  // ── Verify internal secret ──
  const internalSecret = env.INTERNAL_SECRET;
  if (!internalSecret) {
    return jsonResponse({ error: 'Internal endpoint not configured' }, 503);
  }

  const providedSecret = request.headers.get('X-CP-Internal-Secret') || '';
  if (!constantTimeEqual(providedSecret, internalSecret)) {
    return jsonResponse({ error: 'Forbidden' }, 403);
  }

  // ── Parse request body ──
  let body: CreateMembershipRequest;
  try {
    body = await request.json() as CreateMembershipRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  const { userId, tenantId, role } = body;

  // ── Validate required fields ──
  if (!userId || typeof userId !== 'string') {
    return jsonResponse({ error: 'userId is required' }, 400);
  }
  if (!tenantId || typeof tenantId !== 'string') {
    return jsonResponse({ error: 'tenantId is required' }, 400);
  }
  if (!role || typeof role !== 'string') {
    return jsonResponse({ error: 'role is required' }, 400);
  }

  // ── Block dangerous roles ──
  if (BLOCKED_ROLES.has(role)) {
    return jsonResponse({ error: `Role '${role}' cannot be created via this endpoint` }, 403);
  }
  if (!ALLOWED_ROLES.has(role)) {
    return jsonResponse({ error: `Invalid role: ${role}` }, 400);
  }

  // ── Create membership ──
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const membershipId = crypto.randomUUID();

  try {
    await db.createMembership(membershipId, userId, tenantId, role as 'seller' | 'supplier');
  } catch (err: unknown) {
    // Check for UNIQUE constraint violation (membership already exists)
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('UNIQUE') || message.includes('constraint')) {
      return jsonResponse({
        error: 'Membership already exists',
        userId,
        tenantId,
        role,
      }, 409);
    }
    throw err;
  }

  return jsonResponse({
    membershipId,
    userId,
    tenantId,
    role,
  }, 201);
}
