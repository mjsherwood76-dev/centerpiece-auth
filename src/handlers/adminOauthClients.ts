/**
 * Platform-Admin OAuth Third-Party Client Management
 *
 * Routes (all require platform-admin JWT):
 *   POST   /admin/oauth/clients              → Create client (returns one-time plaintext secret)
 *   GET    /admin/oauth/clients              → List clients
 *   GET    /admin/oauth/clients/:id          → Client detail
 *   POST   /admin/oauth/clients/:id/suspend  → Suspend client
 *   POST   /admin/oauth/clients/:id/revoke   → Revoke client (permanent)
 *
 * Auth: Bearer JWT with aud='admin' and platform context (same pattern as
 * customers.ts). Called via the centerpiece-platform-api → AUTH Service Binding.
 *
 * Audit: create/suspend/revoke write to auth structured audit log.
 *
 * Phase 3.18 Session 5.
 *
 * @module handlers/adminOauthClients
 */

import type { Env } from '../types.js';
import { verifyJwt, type JwtPayload } from '../crypto/jwt.js';
import {
  createClient,
  findClientById,
  listClients,
  suspendClient,
  revokeClient,
  validateScopes,
} from '../db.oauthClients.js';
import { logAuthEvent } from '../security/auditLog.js';
import { jsonResponse, jsonError } from '../util/httpJson.js';
import { ConsoleJsonLogger } from '../core/logger.js';

const logger = new ConsoleJsonLogger();

// ─── Auth helpers ───────────────────────────────────────────

interface AuthResult {
  ok: true;
  payload: JwtPayload;
  userId: string;
}

interface AuthFailure {
  ok: false;
  response: Response;
}

/**
 * Require an admin JWT with platform context.
 * Returns the verified payload or an error response.
 */
async function requirePlatformAdmin(
  request: Request,
  env: Env,
): Promise<AuthResult | AuthFailure> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { ok: false, response: jsonError('Missing or invalid Authorization header', 401) };
  }

  const token = authHeader.slice(7);
  const payload = await verifyJwt(token, env.JWT_PUBLIC_KEY);

  if (!payload) {
    return { ok: false, response: jsonError('Invalid or expired token', 401) };
  }

  if (payload.aud !== 'admin') {
    return { ok: false, response: jsonError('Token audience must be admin', 403) };
  }

  const contexts = payload.contexts || {};
  const hasPlatformContext = Array.isArray(contexts.platform) && contexts.platform.length > 0;
  if (!hasPlatformContext) {
    return { ok: false, response: jsonError('Insufficient role: requires platform context', 403) };
  }

  const userId = payload.sub;
  if (!userId) {
    return { ok: false, response: jsonError('Token missing subject', 400) };
  }

  return { ok: true, payload, userId };
}

// ─── Route dispatcher ───────────────────────────────────────

/**
 * Dispatch /admin/oauth/clients/* routes.
 *
 * @returns Response if matched, null if not an admin OAuth client route.
 */
export async function handleAdminOauthClientRoutes(
  request: Request,
  env: Env,
  correlationId: string,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (!path.startsWith('/admin/oauth/clients')) {
    return null;
  }

  // POST /admin/oauth/clients — create
  if (path === '/admin/oauth/clients' && method === 'POST') {
    return handleCreateClient(request, env, correlationId);
  }

  // GET /admin/oauth/clients — list
  if (path === '/admin/oauth/clients' && method === 'GET') {
    return handleListClients(request, env);
  }

  // GET /admin/oauth/clients/:id — detail
  const detailMatch = path.match(/^\/admin\/oauth\/clients\/([^/]+)$/);
  if (detailMatch && method === 'GET') {
    return handleClientDetail(request, env, detailMatch[1]);
  }

  // POST /admin/oauth/clients/:id/suspend
  const suspendMatch = path.match(/^\/admin\/oauth\/clients\/([^/]+)\/suspend$/);
  if (suspendMatch && method === 'POST') {
    return handleSuspendClient(request, env, suspendMatch[1], correlationId);
  }

  // POST /admin/oauth/clients/:id/revoke
  const revokeMatch = path.match(/^\/admin\/oauth\/clients\/([^/]+)\/revoke$/);
  if (revokeMatch && method === 'POST') {
    return handleRevokeClient(request, env, revokeMatch[1], correlationId);
  }

  return null;
}

// ─── Create client ──────────────────────────────────────────

/**
 * POST /admin/oauth/clients
 *
 * Body: { clientName, redirectUris: string[], allowedScopes: string[], contactEmail?: string }
 *
 * Returns: { clientId, clientName, plaintextSecret (one-time), redirectUris, allowedScopes, ... }
 * The plaintext secret is returned ONCE and never retrievable again.
 */
async function handleCreateClient(
  request: Request,
  env: Env,
  correlationId: string,
): Promise<Response> {
  const auth = await requirePlatformAdmin(request, env);
  if (!auth.ok) return auth.response;

  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return jsonError('Invalid request body', 400);
  }

  const clientName = typeof body.clientName === 'string' ? body.clientName.trim() : '';
  if (!clientName) return jsonError('clientName is required', 400);

  if (!Array.isArray(body.redirectUris) || body.redirectUris.length === 0) {
    return jsonError('redirectUris must be a non-empty array', 400);
  }
  const redirectUris = body.redirectUris as unknown[];
  if (!redirectUris.every((u) => typeof u === 'string' && u.startsWith('https://'))) {
    return jsonError('All redirectUris must be strings starting with https://', 400);
  }

  if (!Array.isArray(body.allowedScopes) || body.allowedScopes.length === 0) {
    return jsonError('allowedScopes must be a non-empty array', 400);
  }
  const allowedScopes = body.allowedScopes as unknown[];
  if (!allowedScopes.every((s) => typeof s === 'string')) {
    return jsonError('All allowedScopes must be strings', 400);
  }

  const invalidScopes = validateScopes(allowedScopes as string[]);
  if (invalidScopes.length > 0) {
    return jsonError(`Unsupported scopes: ${invalidScopes.join(', ')}`, 400);
  }

  const contactEmail = typeof body.contactEmail === 'string' ? body.contactEmail.trim() || null : null;

  const clientId = crypto.randomUUID();

  const { client, plaintextSecret } = await createClient(env.AUTH_DB, {
    clientId,
    clientName,
    redirectUris: redirectUris as string[],
    allowedScopes: allowedScopes as string[],
    createdByUserId: auth.userId,
    contactEmail,
  });

  logAuthEvent(logger, {
    event: 'oauth_client_created',
    ip: 'internal',
    route: '/admin/oauth/clients',
    correlationId,
    userId: auth.userId,
    details: { clientId, clientName },
  });

  return jsonResponse({
    clientId: client.clientId,
    clientName: client.clientName,
    redirectUris: client.redirectUris,
    allowedScopes: client.allowedScopes,
    createdAt: client.createdAt,
    createdByUserId: client.createdByUserId,
    status: client.status,
    contactEmail: client.contactEmail,
    // One-time secret — only returned on creation response
    clientSecret: plaintextSecret,
  }, 201);
}

// ─── List clients ───────────────────────────────────────────

/**
 * GET /admin/oauth/clients
 *
 * Query params: status (optional: 'active' | 'suspended' | 'revoked')
 */
async function handleListClients(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await requirePlatformAdmin(request, env);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const statusParam = url.searchParams.get('status');
  const validStatuses = ['active', 'suspended', 'revoked'] as const;
  const status = validStatuses.includes(statusParam as typeof validStatuses[number])
    ? (statusParam as 'active' | 'suspended' | 'revoked')
    : undefined;

  const clients = await listClients(env.AUTH_DB, status ? { status } : undefined);

  return jsonResponse({ clients });
}

// ─── Client detail ──────────────────────────────────────────

/**
 * GET /admin/oauth/clients/:id
 */
async function handleClientDetail(
  request: Request,
  env: Env,
  clientId: string,
): Promise<Response> {
  const auth = await requirePlatformAdmin(request, env);
  if (!auth.ok) return auth.response;

  const client = await findClientById(env.AUTH_DB, clientId);
  if (!client) return jsonError('Client not found', 404);

  return jsonResponse({ client });
}

// ─── Suspend client ─────────────────────────────────────────

/**
 * POST /admin/oauth/clients/:id/suspend
 */
async function handleSuspendClient(
  request: Request,
  env: Env,
  clientId: string,
  correlationId: string,
): Promise<Response> {
  const auth = await requirePlatformAdmin(request, env);
  if (!auth.ok) return auth.response;

  const client = await findClientById(env.AUTH_DB, clientId);
  if (!client) return jsonError('Client not found', 404);

  if (client.status === 'revoked') {
    return jsonError('Cannot suspend a revoked client', 409);
  }

  const ok = await suspendClient(env.AUTH_DB, clientId);
  if (!ok) {
    return jsonError('Failed to suspend client', 500);
  }

  logAuthEvent(logger, {
    event: 'oauth_client_suspended',
    ip: 'internal',
    route: `/admin/oauth/clients/${clientId}/suspend`,
    correlationId,
    userId: auth.userId,
    details: { clientId, clientName: client.clientName },
  });

  return jsonResponse({ clientId, status: 'suspended' });
}

// ─── Revoke client ──────────────────────────────────────────

/**
 * POST /admin/oauth/clients/:id/revoke
 */
async function handleRevokeClient(
  request: Request,
  env: Env,
  clientId: string,
  correlationId: string,
): Promise<Response> {
  const auth = await requirePlatformAdmin(request, env);
  if (!auth.ok) return auth.response;

  const client = await findClientById(env.AUTH_DB, clientId);
  if (!client) return jsonError('Client not found', 404);

  const ok = await revokeClient(env.AUTH_DB, clientId);
  if (!ok) {
    return jsonError('Failed to revoke client', 500);
  }

  logAuthEvent(logger, {
    event: 'oauth_client_revoked',
    ip: 'internal',
    route: `/admin/oauth/clients/${clientId}/revoke`,
    correlationId,
    userId: auth.userId,
    details: { clientId, clientName: client.clientName },
  });

  return jsonResponse({ clientId, status: 'revoked' });
}
