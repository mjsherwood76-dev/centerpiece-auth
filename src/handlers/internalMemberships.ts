/**
 * Internal Membership Endpoints
 *
 * POST   /api/internal/memberships              — Create membership with specified role
 * DELETE /api/internal/memberships              — Delete a non-owner membership
 * GET    /api/internal/memberships/by-tenant    — List non-customer memberships for a tenant
 * GET    /api/internal/memberships/owner-count  — Count active owner memberships for a user
 *
 * All gated by `X-CP-Internal-Secret` header (constant-time comparison).
 *
 * Security:
 * - Gated by shared internal secret (NOT JWT — caller is a Worker, not a browser)
 * - Constant-time comparison prevents timing attacks
 * - NEVER allows `platform_admin` role creation
 * - Owner deletion is forbidden (System Invariant #7)
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';

// ─── Types ──────────────────────────────────────────────────

interface CreateMembershipRequest {
  userId: string;
  tenantId: string;
  role: 'seller' | 'supplier' | 'owner';
}

interface DeleteMembershipRequest {
  userId: string;
  tenantId: string;
  role: string;
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

/**
 * Validate the X-CP-Internal-Secret header.
 * Returns a Response if validation fails, or null if the secret is valid.
 */
function validateInternalSecret(request: Request, env: Env): Response | null {
  const internalSecret = env.INTERNAL_SECRET;
  if (!internalSecret) {
    return jsonResponse({ error: 'Internal endpoint not configured' }, 503);
  }

  const providedSecret = request.headers.get('X-CP-Internal-Secret') || '';
  if (!constantTimeEqual(providedSecret, internalSecret)) {
    return jsonResponse({ error: 'Forbidden' }, 403);
  }

  return null; // Secret is valid
}

// ─── Blocked roles ──────────────────────────────────────────

/** Roles that can NEVER be created via this internal endpoint. */
const BLOCKED_ROLES = new Set(['platform_admin', 'customer']);

/** Roles allowed for creation via this endpoint. */
const ALLOWED_ROLES = new Set(['seller', 'supplier', 'owner']);

// ─── POST Handler ───────────────────────────────────────────

/**
 * Handle POST /api/internal/memberships
 *
 * Creates a tenant membership for a user with the specified role.
 * Gated by X-CP-Internal-Secret header.
 *
 * Request body: { userId: string, tenantId: string, role: 'seller' | 'supplier' | 'owner' }
 * Response: 201 { membershipId, userId, tenantId, role }
 * Errors: 403 (bad secret / blocked role), 400 (bad input), 409 (exists)
 */
async function handlePost(request: Request, env: Env): Promise<Response> {
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
    await db.createMembership(membershipId, userId, tenantId, role as 'seller' | 'supplier' | 'owner');
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

// ─── DELETE Handler ─────────────────────────────────────────

/**
 * Handle DELETE /api/internal/memberships
 *
 * Deletes a tenant membership. Owner deletion is forbidden (System Invariant #7).
 * Gated by X-CP-Internal-Secret header.
 *
 * Request body: { userId: string, tenantId: string, role: string }
 * Response: 200 { deleted: true, userId, tenantId, role }
 * Errors: 403 (owner role / bad secret), 400 (bad input)
 */
async function handleDelete(request: Request, env: Env): Promise<Response> {
  // ── Parse request body ──
  let body: DeleteMembershipRequest;
  try {
    body = await request.json() as DeleteMembershipRequest;
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

  // ── Owner deletion is forbidden (System Invariant #7) ──
  if (role === 'owner') {
    return jsonResponse({
      error: 'Owner removal forbidden. Use tenant archive or ownership transfer.',
    }, 403);
  }

  // ── Delete membership ──
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  await db.deleteMembership(userId, tenantId, role);

  return jsonResponse({
    deleted: true,
    userId,
    tenantId,
    role,
  }, 200);
}

// ─── GET by-tenant Handler ──────────────────────────────────

/**
 * Handle GET /api/internal/memberships/by-tenant?tenantId=X
 *
 * Lists all non-customer memberships for a tenant (with user details).
 * Gated by X-CP-Internal-Secret header.
 *
 * Response: [{ userId, email, name, role, status, createdAt }]
 */
async function handleGetByTenant(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const tenantId = url.searchParams.get('tenantId')?.trim();
  if (!tenantId) {
    return jsonResponse({ error: 'tenantId query parameter is required' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const memberships = await db.getMembershipsByTenant(tenantId);

  return jsonResponse(
    memberships.map(m => ({
      userId: m.user_id,
      email: m.email,
      name: m.name,
      role: m.role,
      status: m.status,
      createdAt: m.created_at,
    })),
    200
  );
}

// ─── GET owner-count Handler ────────────────────────────────

/**
 * Handle GET /api/internal/memberships/owner-count?userId=X
 *
 * Returns the count of active owner memberships for a user.
 * Used to enforce per-user tenant limit (5).
 * Gated by X-CP-Internal-Secret header.
 *
 * Response: { count: number }
 */
async function handleGetOwnerCount(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const userId = url.searchParams.get('userId')?.trim();
  if (!userId) {
    return jsonResponse({ error: 'userId query parameter is required' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const count = await db.countOwnerMemberships(userId);

  return jsonResponse({ count }, 200);
}

// ─── Unified Handler ────────────────────────────────────────

/**
 * Route handler for /api/internal/memberships* endpoints.
 * Validates internal secret, then dispatches to method-specific handlers.
 */
export async function handleInternalMemberships(request: Request, env: Env): Promise<Response> {
  // ── Verify internal secret (shared across all methods) ──
  const secretError = validateInternalSecret(request, env);
  if (secretError) return secretError;

  const method = request.method;
  const url = new URL(request.url);
  const path = url.pathname;

  if (method === 'POST' && path === '/api/internal/memberships') {
    return handlePost(request, env);
  }

  if (method === 'DELETE' && path === '/api/internal/memberships') {
    return handleDelete(request, env);
  }

  if (method === 'GET' && path === '/api/internal/memberships/by-tenant') {
    return handleGetByTenant(request, env);
  }

  if (method === 'GET' && path === '/api/internal/memberships/owner-count') {
    return handleGetOwnerCount(request, env);
  }

  return jsonResponse({ error: 'Not found' }, 404);
}
