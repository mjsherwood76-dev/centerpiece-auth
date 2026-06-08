/**
 * Internal Team-Invite Endpoints (Fix_Team_Invites S3, ADR 020)
 *
 * POST   /api/internal/invites              — Create an invite OR signal that the
 *                                             user already exists (auto-grant branch)
 * GET    /api/internal/invites/by-tenant    — List pending invites for a tenant
 * DELETE /api/internal/invites/:id          — Revoke a pending invite
 *
 * All gated by `X-CP-Internal-Secret` (constant-time comparison). The caller is
 * platform-api (a Worker), never a browser.
 *
 * The `{ exists: true|false }` POST response shape is INTERNAL-ONLY: it lets
 * platform-api decide grant-directly vs send-invite. platform-api MUST collapse
 * it to a uniform UI-facing response (review R3 — no account enumeration).
 *
 * Security:
 * - Context+subRole validated against CONTEXT_ROLES (no `owner`).
 * - Platform context only on __platform__ tenant + @<allowed-domain> email gate.
 * - Token is generated here, returned in plaintext ONCE; only its hash is stored.
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { ConsoleJsonLogger } from '../core/logger.js';
import { logAuthEvent } from '../security/auditLog.js';
import { requireInternalSecret } from '../security/internalSecret.js';
import { isPlatformEmailAllowed } from '../security/emailDomainCheck.js';
import { jsonResponse } from '../util/httpJson.js';
import { generateInviteToken, hashInviteToken } from '../crypto/inviteToken.js';
import { INVITE_EXPIRY_DAYS } from '../db.invites.js';

const logger = new ConsoleJsonLogger();

// ─── Context-SubRole Validation (mirror of internalMemberships) ───
// `owner` is intentionally excluded — invites never create owners.
const CONTEXT_ROLES: Record<string, Set<string>> = {
  seller: new Set(['manager', 'designer', 'analyst', 'marketer', 'merchandiser']),
  supplier: new Set(['manager', 'designer', 'analyst', 'marketer', 'operator']),
  platform: new Set(['manager', 'designer', 'analyst', 'marketer', 'support', 'operations', 'finance']),
};

interface CreateInviteRequest {
  email: string;
  tenantId: string;
  context: 'seller' | 'supplier' | 'platform';
  subRole: string;
  invitedBy: string;
}

function correlationOf(request: Request): string {
  return request.headers.get('x-request-id')
    || request.headers.get('x-correlation-id')
    || 'unknown';
}

// ─── POST /api/internal/invites ─────────────────────────────

async function handleCreate(request: Request, env: Env): Promise<Response> {
  let body: CreateInviteRequest;
  try {
    body = await request.json() as CreateInviteRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  const emailRaw = body.email;
  const { tenantId, context, subRole, invitedBy } = body;

  // ── Required-field validation ──
  if (!emailRaw || typeof emailRaw !== 'string') {
    return jsonResponse({ error: 'email is required' }, 400);
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
  if (!invitedBy || typeof invitedBy !== 'string') {
    return jsonResponse({ error: 'invitedBy is required' }, 400);
  }

  const email = emailRaw.trim().toLowerCase();
  // Minimal shape check — platform-api does the UX-facing validation.
  if (!email.includes('@') || email.startsWith('@') || email.endsWith('@')) {
    return jsonResponse({ error: 'email is malformed' }, 400);
  }

  // ── Context + subRole validation (no owner) ──
  const validRoles = CONTEXT_ROLES[context];
  if (!validRoles) {
    return jsonResponse({ error: `Invalid context: ${context}` }, 400);
  }
  if (!validRoles.has(subRole)) {
    return jsonResponse({ error: `Invalid subRole '${subRole}' for context '${context}'` }, 400);
  }

  // ── Platform context constraints (tenant + email domain) ──
  if (context === 'platform') {
    if (tenantId !== '__platform__') {
      return jsonResponse({ error: 'Platform context is only valid on __platform__ tenant' }, 400);
    }
    if (!isPlatformEmailAllowed(email, env)) {
      const domain = email.split('@')[1] ?? '';
      logAuthEvent(logger, {
        event: 'invite.platform_domain_rejected',
        ip: request.headers.get('CF-Connecting-IP') || 'internal',
        route: '/api/internal/invites',
        correlationId: correlationOf(request),
        details: { domain },
      });
      return jsonResponse({
        error: {
          code: 'platform_role.email_domain_restricted',
          message: 'Platform role requires an email address on an allowed domain.',
        },
      }, 403);
    }
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Existence branch: if a user already has an account, do NOT create an
  //    invite — platform-api grants the membership directly. ──
  const existing = await db.getUserByEmailPublic(email);
  if (existing) {
    logAuthEvent(logger, {
      event: 'invite.exists',
      ip: request.headers.get('CF-Connecting-IP') || 'internal',
      route: '/api/internal/invites',
      correlationId: correlationOf(request),
      userId: existing.id,
      details: { tenantId, context, subRole },
    });
    return jsonResponse({ exists: true, userId: existing.id }, 200);
  }

  // ── New person: reject if a live (unexpired, unaccepted) invite already
  //    exists for this exact tuple. Expired rows are auto-purged by createInvite. ──
  if (await db.hasPendingInvite(email, tenantId, context, subRole)) {
    return jsonResponse({
      error: { code: 'invite.already_pending', message: 'An invitation is already pending for this email and role.' },
    }, 409);
  }

  // ── Generate token, store hash, return plaintext token ONCE. ──
  const id = crypto.randomUUID();
  const token = generateInviteToken();
  const tokenHash = await hashInviteToken(token);

  try {
    await db.createInvite({ id, email, tenantId, context, subRole, tokenHash, invitedBy });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('UNIQUE') || message.includes('constraint')) {
      // Race: a live invite slipped in between the check and the insert.
      return jsonResponse({
        error: { code: 'invite.already_pending', message: 'An invitation is already pending for this email and role.' },
      }, 409);
    }
    throw err;
  }

  // Compute expiresAt for the caller (email copy + audit). Mirrors the DB value.
  const expiresAt = new Date(Date.now() + INVITE_EXPIRY_DAYS * 24 * 60 * 60 * 1000).toISOString();

  logAuthEvent(logger, {
    event: 'invite.create',
    ip: request.headers.get('CF-Connecting-IP') || 'internal',
    route: '/api/internal/invites',
    correlationId: correlationOf(request),
    userId: invitedBy,
    details: { inviteId: id, tenantId, context, subRole, expiresInDays: INVITE_EXPIRY_DAYS },
  });

  return jsonResponse({
    exists: false,
    inviteId: id,
    token,            // plaintext, returned ONCE — caller builds the invite URL
    expiresAt,
    expiresInDays: INVITE_EXPIRY_DAYS,
  }, 201);
}

// ─── GET /api/internal/invites/by-tenant?tenantId=X ─────────

async function handleListByTenant(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const tenantId = url.searchParams.get('tenantId')?.trim();
  if (!tenantId) {
    return jsonResponse({ error: 'tenantId query parameter is required' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const invites = await db.getInvitesByTenant(tenantId);

  return jsonResponse(
    invites.map(inv => ({
      id: inv.id,
      email: inv.email,
      tenantId: inv.tenant_id,
      context: inv.context,
      subRole: inv.sub_role,
      invitedBy: inv.invited_by,
      createdAt: inv.created_at,
      expiresAt: inv.expires_at,
    })),
    200,
  );
}

// ─── DELETE /api/internal/invites/:id ───────────────────────

async function handleRevoke(request: Request, env: Env, inviteId: string): Promise<Response> {
  if (!inviteId) {
    return jsonResponse({ error: 'invite id is required' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const deleted = await db.deleteInvite(inviteId);

  logAuthEvent(logger, {
    event: 'invite.revoke',
    ip: request.headers.get('CF-Connecting-IP') || 'internal',
    route: '/api/internal/invites',
    correlationId: correlationOf(request),
    details: { inviteId, deleted },
  });

  // Idempotent revoke — 200 whether or not a row existed.
  return jsonResponse({ deleted }, 200);
}

// ─── Unified Handler ────────────────────────────────────────

export async function handleInternalInvites(request: Request, env: Env): Promise<Response> {
  const denied = requireInternalSecret(request, env);
  if (denied) return denied;

  const method = request.method;
  const url = new URL(request.url);
  const path = url.pathname;

  if (method === 'POST' && path === '/api/internal/invites') {
    return handleCreate(request, env);
  }

  if (method === 'GET' && path === '/api/internal/invites/by-tenant') {
    return handleListByTenant(request, env);
  }

  if (method === 'DELETE' && path.startsWith('/api/internal/invites/')) {
    const inviteId = decodeURIComponent(path.slice('/api/internal/invites/'.length));
    return handleRevoke(request, env, inviteId);
  }

  return jsonResponse({ error: 'Not found' }, 404);
}
