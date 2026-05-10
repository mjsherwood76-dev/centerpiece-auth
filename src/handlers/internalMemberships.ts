/**
 * Internal Membership Endpoints
 *
 * POST   /api/internal/memberships              — Create membership with specified context + subRole
 * DELETE /api/internal/memberships              — Delete a non-owner membership
 * GET    /api/internal/memberships/by-tenant    — List non-customer memberships for a tenant
 * GET    /api/internal/memberships/owner-count  — Count active seller-owner memberships for a user
 * PATCH  /api/internal/memberships/suspend      — Suspend all memberships for a user in a context
 * PATCH  /api/internal/memberships/reactivate   — Reactivate suspended memberships for a user in a context
 *
 * All gated by `X-CP-Internal-Secret` header (constant-time comparison).
 *
 * Security:
 * - Gated by shared internal secret (NOT JWT — caller is a Worker, not a browser)
 * - Constant-time comparison prevents timing attacks
 * - Context+subRole validated against CONTEXT_ROLES map
 * - Platform context only allowed on __platform__ tenant
 * - Owner deletion is forbidden (System Invariant #2)
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { ConsoleJsonLogger } from '../core/logger.js';
import { logAuthEvent } from '../security/auditLog.js';
import { jsonResponse } from '../util/httpJson.js';

const logger = new ConsoleJsonLogger();

// ─── Types ──────────────────────────────────────────────────

interface CreateMembershipRequest {
  userId: string;
  tenantId: string;
  context: 'seller' | 'supplier' | 'platform';
  subRole: 'owner' | 'manager' | 'designer' | 'analyst' | 'marketer'
    | 'merchandiser' | 'operator' | 'support' | 'operations' | 'finance';
}

interface DeleteMembershipRequest {
  userId: string;
  tenantId: string;
  context: string;
  subRole: string;
}

// ─── Helpers ────────────────────────────────────────────────

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

// ─── Context-SubRole Validation ───────────────────────────────────

/** Valid sub-roles per context. Single source of truth for context↔sub-role validity. */
const CONTEXT_ROLES: Record<string, Set<string>> = {
  seller: new Set(['owner', 'manager', 'designer', 'analyst', 'marketer', 'merchandiser']),
  supplier: new Set(['owner', 'manager', 'designer', 'analyst', 'marketer', 'operator']),
  platform: new Set(['owner', 'manager', 'designer', 'analyst', 'marketer', 'support', 'operations', 'finance']),
};

// ─── POST Handler ───────────────────────────────────────────

/**
 * Handle POST /api/internal/memberships
 *
 * Creates a tenant membership for a user with the specified context + subRole.
 * Gated by X-CP-Internal-Secret header.
 *
 * Request body: { userId, tenantId, context, subRole }
 * Response: 201 { membershipId, userId, tenantId, context, subRole }
 * Errors: 403 (bad secret), 400 (bad input), 409 (exists)
 */
async function handlePost(request: Request, env: Env): Promise<Response> {
  // ── Parse request body ──
  let body: CreateMembershipRequest;
  try {
    body = await request.json() as CreateMembershipRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  const { userId, tenantId, context, subRole } = body;

  // ── Validate required fields ──
  if (!userId || typeof userId !== 'string') {
    return jsonResponse({ error: 'userId is required' }, 400);
  }
  if (!tenantId || typeof tenantId !== 'string') {
    return jsonResponse({ error: 'tenantId is required' }, 400);
  }
  if (!context || typeof context !== 'string') {
    return jsonResponse({ error: 'context is required' }, 400);
  }
  if (!subRole || typeof subRole !== 'string') {
    return jsonResponse({ error: 'subRole is required' }, 400);
  }

  // ── Validate context ──
  const validRoles = CONTEXT_ROLES[context];
  if (!validRoles) {
    return jsonResponse({ error: `Invalid context: ${context}` }, 400);
  }

  // ── Validate subRole for this context ──
  if (!validRoles.has(subRole)) {
    return jsonResponse({ error: `Invalid subRole '${subRole}' for context '${context}'` }, 400);
  }

  // ── Enforce platform context only on __platform__ tenant ──
  if (context === 'platform' && tenantId !== '__platform__') {
    return jsonResponse({ error: 'Platform context is only valid on __platform__ tenant' }, 400);
  }

  // ── Enforce @centerpiecelab.com email for platform context (Defense-in-Depth Layer 1) ──
  if (context === 'platform') {
    const db = new AuthDB(env.AUTH_DB);
    await db.enableForeignKeys();
    const user = await db.getUserById(userId);
    if (!user || !user.email.endsWith('@centerpiecelab.com')) {
      return jsonResponse({ error: 'Platform context requires @centerpiecelab.com email' }, 400);
    }
  }

  // ── Create membership ──
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const membershipId = crypto.randomUUID();

  try {
    await db.createMembership(membershipId, userId, tenantId, context as 'seller' | 'supplier' | 'platform', subRole);
  } catch (err: unknown) {
    // Check for UNIQUE constraint violation (membership already exists)
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('UNIQUE') || message.includes('constraint')) {
      return jsonResponse({
        error: 'Membership already exists',
        userId,
        tenantId,
        context,
        subRole,
      }, 409);
    }
    throw err;
  }

  const correlationId = request.headers.get('x-request-id')
    || request.headers.get('x-correlation-id')
    || 'unknown';

  logAuthEvent(logger, {
    event: 'membership.create',
    ip: request.headers.get('CF-Connecting-IP') || 'internal',
    route: '/api/internal/memberships',
    correlationId,
    details: { userId, tenantId, context, subRole },
  });

  return jsonResponse({
    membershipId,
    userId,
    tenantId,
    context,
    subRole,
  }, 201);
}

// ─── DELETE Handler ─────────────────────────────────────────

/**
 * Handle DELETE /api/internal/memberships
 *
 * Deletes a tenant membership. Owner deletion is forbidden (System Invariant #2).
 * Gated by X-CP-Internal-Secret header.
 *
 * Request body: { userId, tenantId, context, subRole }
 * Response: 200 { deleted: true, userId, tenantId, context, subRole }
 * Errors: 403 (owner subRole / bad secret), 400 (bad input)
 */
async function handleDelete(request: Request, env: Env): Promise<Response> {
  // ── Parse request body ──
  let body: DeleteMembershipRequest;
  try {
    body = await request.json() as DeleteMembershipRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  const { userId, tenantId, context, subRole } = body;

  // ── Validate required fields ──
  if (!userId || typeof userId !== 'string') {
    return jsonResponse({ error: 'userId is required' }, 400);
  }
  if (!tenantId || typeof tenantId !== 'string') {
    return jsonResponse({ error: 'tenantId is required' }, 400);
  }
  if (!context || typeof context !== 'string') {
    return jsonResponse({ error: 'context is required' }, 400);
  }
  if (!subRole || typeof subRole !== 'string') {
    return jsonResponse({ error: 'subRole is required' }, 400);
  }

  // ── Owner deletion is forbidden (System Invariant #2) ──
  if (subRole === 'owner') {
    return jsonResponse({
      error: 'Owner removal forbidden. Use tenant archive or ownership transfer.',
    }, 403);
  }

  // ── Delete membership ──
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  await db.deleteMembership(userId, tenantId, context, subRole);

  const correlationId = request.headers.get('x-request-id')
    || request.headers.get('x-correlation-id')
    || 'unknown';

  logAuthEvent(logger, {
    event: 'membership.delete',
    ip: request.headers.get('CF-Connecting-IP') || 'internal',
    route: '/api/internal/memberships',
    correlationId,
    details: { userId, tenantId, context, subRole },
  });

  return jsonResponse({
    deleted: true,
    userId,
    tenantId,
    context,
    subRole,
  }, 200);
}

// ─── GET by-tenant Handler ──────────────────────────────────

/**
 * Handle GET /api/internal/memberships/by-tenant?tenantId=X
 *
 * Lists all non-customer memberships for a tenant (with user details).
 * Gated by X-CP-Internal-Secret header.
 *
 * Response: [{ userId, email, name, context, subRole, status, createdAt }]
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
      context: m.context,
      subRole: m.sub_role,
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

  if (method === 'PATCH' && path === '/api/internal/memberships/suspend') {
    return handleSuspend(request, env);
  }

  if (method === 'PATCH' && path === '/api/internal/memberships/reactivate') {
    return handleReactivate(request, env);
  }

  return jsonResponse({ error: 'Not found' }, 404);
}

// ─── PATCH suspend Handler ──────────────────────────────────

/**
 * Handle PATCH /api/internal/memberships/suspend
 *
 * Suspends all non-owner memberships for a user in a given context on a tenant.
 * Suspended memberships are excluded from JWT building.
 *
 * Request body: { userId, tenantId, context }
 * Response: 200 { suspended: true, count: number }
 */
async function handleSuspend(request: Request, env: Env): Promise<Response> {
  let body: { userId?: string; tenantId?: string; context?: string };
  try {
    body = await request.json() as { userId?: string; tenantId?: string; context?: string };
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  const { userId, tenantId, context } = body;
  if (!userId || typeof userId !== 'string') {
    return jsonResponse({ error: 'userId is required' }, 400);
  }
  if (!tenantId || typeof tenantId !== 'string') {
    return jsonResponse({ error: 'tenantId is required' }, 400);
  }
  if (!context || typeof context !== 'string') {
    return jsonResponse({ error: 'context is required' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const count = await db.suspendMemberships(userId, tenantId, context);

  return jsonResponse({ suspended: true, count }, 200);
}

// ─── PATCH reactivate Handler ───────────────────────────────

/**
 * Handle PATCH /api/internal/memberships/reactivate
 *
 * Reactivates suspended memberships for a user in a given context on a tenant.
 *
 * Request body: { userId, tenantId, context }
 * Response: 200 { reactivated: true, count: number }
 */
async function handleReactivate(request: Request, env: Env): Promise<Response> {
  let body: { userId?: string; tenantId?: string; context?: string };
  try {
    body = await request.json() as { userId?: string; tenantId?: string; context?: string };
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  const { userId, tenantId, context } = body;
  if (!userId || typeof userId !== 'string') {
    return jsonResponse({ error: 'userId is required' }, 400);
  }
  if (!tenantId || typeof tenantId !== 'string') {
    return jsonResponse({ error: 'tenantId is required' }, 400);
  }
  if (!context || typeof context !== 'string') {
    return jsonResponse({ error: 'context is required' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const count = await db.reactivateMemberships(userId, tenantId, context);

  return jsonResponse({ reactivated: true, count }, 200);
}
