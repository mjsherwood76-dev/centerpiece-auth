/**
 * Public Accept-Invite Flow (Fix_Team_Invites S4, ADR 020) — HIGH RISK
 *
 * GET  /accept-invite?token=T  — render the accept page (register OR sign-in,
 *                                email pre-filled + LOCKED to the invite's email).
 * POST /accept-invite          — verify token (single-use), create user OR
 *                                authenticate existing, create the membership
 *                                (active), mark accepted, issue session + admin
 *                                auth code, redirect to the hub admin.
 *
 * Security invariants (NON-NEGOTIABLE):
 * - Token is looked up by SHA-256 hash; plaintext is never stored.
 * - Single-use: markInviteAccepted() only transitions an unaccepted+unexpired row;
 *   the POST re-verifies the token in the same request that creates the membership.
 * - Email binding: the account email is ALWAYS the invite's email (the form email
 *   field is locked/ignored server-side) — a token cannot be redeemed for a
 *   different address.
 * - Redirect target is DERIVED SERVER-SIDE from the invite's context/tenant and
 *   re-validated via redirectValidator — never taken from a client param.
 * - Welcome email is suppressed (the invitee already received team-invite).
 * - No account-enumeration leak: the accept page reveals only what the holder of
 *   the (secret) token is entitled to see — that THIS invite's email has/has not
 *   an account, which the inviter already knew.
 *
 * Membership creation reuses the same createMembership path as the internal
 * membership endpoint; account creation reuses register.ts's PBKDF2 hashing.
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import type { InviteRow } from '../db.types.js';
import { hashPassword, verifyPassword } from '../crypto/passwords.js';
import {
  generateRefreshToken,
  hashRefreshToken,
  generateAuthCode,
  hashAuthCode,
  generateUUID,
  buildRefreshCookieHeader,
} from '../crypto/refreshTokens.js';
import { hashInviteToken } from '../crypto/inviteToken.js';
import { validateRedirectUrl } from '../security/redirectValidator.js';
import { isPlatformEmailAllowed } from '../security/emailDomainCheck.js';
import { loadTenantBranding } from '../branding.js';
import { buildDeviceLabel, buildDeviceFingerprint } from '../security/deviceLabel.js';
import { parseRequestBody } from '../util/parseRequestBody.js';
import { renderAuthPage, escapeHtml, escapeAttr } from '../pages/renderer.js';
import { isPasswordBreached } from '../security/breachedPassword.js';
import { ConsoleJsonLogger } from '../core/logger.js';
import { logAuthEvent } from '../security/auditLog.js';

const logger = new ConsoleJsonLogger();

// ─── Invite-state resolution ────────────────────────────────

type InviteState =
  | { ok: true; invite: InviteRow }
  | { ok: false; reason: 'not_found' | 'expired' | 'accepted' };

/**
 * Look up an invite by raw token and classify its state. Expiry is computed in
 * SQL-comparable form: `expires_at` is a `datetime('now')`-format text, so we
 * compare against the same format.
 */
async function resolveInvite(db: AuthDB, rawToken: string): Promise<InviteState> {
  if (!rawToken) return { ok: false, reason: 'not_found' };
  const tokenHash = await hashInviteToken(rawToken);
  const invite = await db.getInviteByTokenHash(tokenHash);
  if (!invite) return { ok: false, reason: 'not_found' };
  if (invite.accepted_at) return { ok: false, reason: 'accepted' };
  // expires_at is "YYYY-MM-DD HH:MM:SS" UTC; compare lexically against the same.
  const nowSql = new Date().toISOString().slice(0, 19).replace('T', ' ');
  if (invite.expires_at <= nowSql) return { ok: false, reason: 'expired' };
  return { ok: true, invite };
}

/** Bare host for the admin hub, per environment. */
function hubOrigin(env: Env): string {
  const suffix = env.ENVIRONMENT === 'production' ? 'com' : 'dev';
  return `https://hub.centerpiecelab.${suffix}`;
}

/**
 * Derive + validate the post-accept redirect target SERVER-SIDE from the invite.
 * seller/supplier → hub root; platform → hub /platform. The path is carried as
 * `returnTo` through the SPA callback. Returns the validated hub origin or null
 * if (unexpectedly) the controlled-suffix validation fails.
 */
async function deriveAcceptRedirect(
  env: Env,
  invite: InviteRow,
): Promise<{ origin: string; returnTo: string } | null> {
  const origin = hubOrigin(env);
  const validation = await validateRedirectUrl(`${origin}/`, env.TENANT_CONFIGS, env.ENVIRONMENT);
  if (!validation.valid) return null;
  const returnTo = invite.context === 'platform' ? '/platform' : '/';
  return { origin: validation.origin, returnTo };
}

// ─── GET /accept-invite ─────────────────────────────────────

export async function handleAcceptInvitePage(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const rawToken = (url.searchParams.get('token') || '').trim();
  const errorCode = url.searchParams.get('error') || '';

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const state = await resolveInvite(db, rawToken);
  const branding = await loadTenantBranding(null, env);

  if (!state.ok) {
    return renderInviteError(env, branding, state.reason);
  }

  const invite = state.invite;
  const existingUser = await db.getUserByEmail(invite.email);
  const roleLabel = `${invite.context} ${invite.sub_role}`;

  // The account email is the invite's email, displayed read-only and submitted
  // via a hidden field is NOT needed — the server always uses the invite email.
  const errorHtml = errorCode
    ? `<div class="auth-error" data-visible="true">${escapeHtml(getErrorMessage(errorCode))}</div>`
    : '<div class="auth-error" id="auth-error"></div>';

  const body = existingUser
    ? renderSignInBody(env, rawToken, invite.email, roleLabel, errorHtml)
    : renderRegisterBody(env, rawToken, invite.email, roleLabel, errorHtml);

  const html = renderAuthPage(branding, { title: 'Accept Invitation', body }, env.PLATFORM_DOMAIN);
  return htmlResponse(html);
}

function renderRegisterBody(env: Env, token: string, email: string, roleLabel: string, errorHtml: string): string {
  return `
    <h1 class="auth-card__title">Accept your invitation</h1>
    <p class="auth-card__subtitle">You've been invited to join as ${escapeHtml(roleLabel)}. Create your account to continue.</p>
    ${errorHtml}
    <form class="auth-form" method="POST" action="${escapeAttr(env.AUTH_DOMAIN)}/accept-invite" id="accept-form">
      <input type="hidden" name="token" value="${escapeAttr(token)}">
      <div class="form-group">
        <label class="form-label" for="email">Email</label>
        <input class="form-input" type="email" id="email" name="email" value="${escapeAttr(email)}" readonly autocomplete="email">
      </div>
      <div class="form-group">
        <label class="form-label" for="name">Name</label>
        <input class="form-input" type="text" id="name" name="name" placeholder="Your name" required autocomplete="name" autofocus>
      </div>
      <div class="form-group">
        <label class="form-label" for="password">Password</label>
        <input class="form-input" type="password" id="password" name="password" placeholder="Create a password" required autocomplete="new-password" minlength="8">
      </div>
      <div class="form-group">
        <label class="form-label" for="confirm-password">Confirm Password</label>
        <input class="form-input" type="password" id="confirm-password" name="confirmPassword" placeholder="Confirm your password" required autocomplete="new-password" minlength="8">
      </div>
      <button class="btn-primary" type="submit">Accept &amp; create account</button>
    </form>`;
}

function renderSignInBody(env: Env, token: string, email: string, roleLabel: string, errorHtml: string): string {
  return `
    <h1 class="auth-card__title">Accept your invitation</h1>
    <p class="auth-card__subtitle">You've been invited to join as ${escapeHtml(roleLabel)}. Sign in to accept.</p>
    ${errorHtml}
    <form class="auth-form" method="POST" action="${escapeAttr(env.AUTH_DOMAIN)}/accept-invite" id="accept-form">
      <input type="hidden" name="token" value="${escapeAttr(token)}">
      <div class="form-group">
        <label class="form-label" for="email">Email</label>
        <input class="form-input" type="email" id="email" name="email" value="${escapeAttr(email)}" readonly autocomplete="email">
      </div>
      <div class="form-group">
        <label class="form-label" for="password">Password</label>
        <input class="form-input" type="password" id="password" name="password" placeholder="Your password" required autocomplete="current-password" autofocus>
      </div>
      <button class="btn-primary" type="submit">Sign in &amp; accept</button>
    </form>`;
}

// ─── POST /accept-invite ────────────────────────────────────

export async function handleAcceptInvite(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  let token: string;
  let password: string;
  let confirmPassword: string;
  let name: string;
  try {
    const body = await parseRequestBody(request);
    token = (body.token || '').trim();
    password = body.password || '';
    confirmPassword = body.confirmPassword || '';
    name = (body.name || '').trim();
    // NOTE: body.email is intentionally ignored — the account email is always the
    // invite's email (email binding). The form field is read-only display only.
  } catch {
    return errorRedirect(env, '', 'invalid_request');
  }

  // ── Re-verify the token (single-use, unexpired, unaccepted) ──
  const state = await resolveInvite(db, token);
  if (!state.ok) {
    // No token echoed back on a dead invite — render the terminal error page.
    return renderInviteError(env, await loadTenantBranding(null, env), state.reason);
  }
  const invite = state.invite;

  // ── Defense-in-depth: re-assert the platform email-domain gate at accept time ──
  if (invite.context === 'platform' && !isPlatformEmailAllowed(invite.email, env)) {
    return renderInviteError(env, await loadTenantBranding(null, env), 'not_found');
  }

  const correlationId = request.headers.get('x-correlation-id') || 'unknown';
  const existingUser = await db.getUserByEmail(invite.email);
  let userId: string;

  if (existingUser) {
    // ── Existing account: authenticate (generic failure, no enumeration) ──
    if (!existingUser.password_hash || !(await verifyPassword(password, existingUser.password_hash))) {
      return errorRedirect(env, token, 'invalid_credentials');
    }
    userId = existingUser.id;
  } else {
    // ── New account: validate password, create user ──
    if (password.length < 8) {
      return errorRedirect(env, token, 'password_weak');
    }
    if (password !== confirmPassword) {
      return errorRedirect(env, token, 'password_mismatch');
    }
    if (await isPasswordBreached(password, env)) {
      return errorRedirect(env, token, 'password_breached');
    }
    userId = generateUUID();
    await db.insertUser({
      id: userId,
      email: invite.email,
      password_hash: await hashPassword(password),
      name: name || invite.email.split('@')[0],
      // Accepting an invite proves control of the mailbox the token was sent to.
      email_verified: true,
    });
    // NOTE: the standard welcome email is intentionally NOT sent here — the
    // invitee already received team-invite (review Q2 de-dup).
  }

  // ── Derive + validate the redirect target server-side BEFORE consuming the
  //    invite, so a (theoretical) redirect-validation failure cannot burn the
  //    single-use token. hub is a controlled suffix → this never fails in
  //    practice, but fail-closed before the mutation is the correct ordering. ──
  const target = await deriveAcceptRedirect(env, invite);
  if (!target) {
    return renderInviteError(env, await loadTenantBranding(null, env), 'invalid_request');
  }

  // ── Mark the invite accepted (single-use guard). If this returns false,
  //    another request already consumed it (or it just expired) — abort before
  //    creating a membership so a replay cannot double-grant. ──
  const claimed = await db.markInviteAccepted(invite.id);
  if (!claimed) {
    return renderInviteError(env, await loadTenantBranding(null, env), 'accepted');
  }

  // ── Create the membership (active). Idempotent against an already-existing
  //    membership for the same tuple (e.g. re-accept race after a prior grant). ──
  try {
    await db.createMembership(
      generateUUID(),
      userId,
      invite.tenant_id,
      invite.context,
      invite.sub_role,
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    // A duplicate membership is acceptable — the grant already exists; proceed.
    if (!(message.includes('UNIQUE') || message.includes('constraint'))) {
      throw err;
    }
  }

  logAuthEvent(logger, {
    event: 'invite.accept',
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown',
    route: '/accept-invite',
    userAgent: request.headers.get('User-Agent'),
    statusCode: 302,
    correlationId,
    userId,
    details: { inviteId: invite.id, tenantId: invite.tenant_id, context: invite.context, subRole: invite.sub_role, newAccount: !existingUser },
  });

  // ── Issue refresh-token session on the auth domain ──
  const loginIat = Math.floor(Date.now() / 1000);
  const refreshToken = generateRefreshToken();
  const refreshTokenId = generateUUID();
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const ua = request.headers.get('User-Agent');
  await db.insertRefreshToken({
    id: refreshTokenId,
    user_id: userId,
    token_hash: await hashRefreshToken(refreshToken),
    family_id: generateUUID(),
    expires_at: loginIat + refreshTtlDays * 24 * 60 * 60,
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'),
    user_agent: ua,
    device_remembered: 0,
    device_label: buildDeviceLabel(ua),
    device_fingerprint: await buildDeviceFingerprint(ua, request.headers.get('CF-IPCountry')),
    login_iat: loginIat,
  });

  // ── Generate a NON-PKCE admin auth code (same shape as the silent-refresh
  //    top-level refresh code; the SPA Callback exchanges it without a verifier). ──
  const authCode = generateAuthCode();
  const codeTtlSeconds = parseInt(env.AUTH_CODE_TTL_SECONDS || '60', 10);
  await db.insertAuthCode({
    code_hash: await hashAuthCode(authCode),
    user_id: userId,
    tenant_id: invite.tenant_id,
    redirect_origin: target.origin,
    aud: 'admin',
    expires_at: loginIat + codeTtlSeconds,
    code_challenge: null,          // non-PKCE — gated by the refresh cookie + single-use code
    code_challenge_method: null,
    refresh_token_id: refreshTokenId,
  });

  // ── Redirect into the hub SPA callback ──
  const callbackUrl = new URL('/auth/callback', target.origin);
  callbackUrl.searchParams.set('code', authCode);
  callbackUrl.searchParams.set('returnTo', target.returnTo);

  return new Response(null, {
    status: 302,
    headers: {
      Location: callbackUrl.toString(),
      'Set-Cookie': buildRefreshCookieHeader(refreshToken, refreshTtlDays, env.AUTH_DOMAIN),
      'Cache-Control': 'no-store',
    },
  });
}

// ─── Helpers ────────────────────────────────────────────────

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

function renderInviteError(
  env: Env,
  branding: Awaited<ReturnType<typeof loadTenantBranding>>,
  reason: 'not_found' | 'expired' | 'accepted' | 'invalid_request',
): Response {
  const message = reason === 'expired'
    ? 'This invitation has expired. Ask whoever invited you to send a new one.'
    : reason === 'accepted'
      ? 'This invitation has already been used. Try signing in instead.'
      : 'This invitation link is not valid. Ask whoever invited you to send a new one.';
  const body = `
    <h1 class="auth-card__title">Invitation unavailable</h1>
    <p class="auth-card__subtitle">${escapeHtml(message)}</p>
    <p class="auth-footer-link">
      <a class="auth-link" href="${escapeAttr(env.AUTH_DOMAIN)}/login?audience=admin">Go to sign in</a>
    </p>`;
  const html = renderAuthPage(branding, { title: 'Invitation unavailable', body }, env.PLATFORM_DOMAIN);
  return htmlResponse(html, 200);
}

/** Redirect back to the accept page (preserving the token) with an error code. */
function errorRedirect(env: Env, token: string, error: string): Response {
  const params = new URLSearchParams();
  if (token) params.set('token', token);
  params.set('error', error);
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.AUTH_DOMAIN}/accept-invite?${params.toString()}`,
      'Cache-Control': 'no-store',
    },
  });
}

function getErrorMessage(code: string): string {
  switch (code) {
    case 'invalid_credentials':
      return 'Invalid email or password.';
    case 'password_weak':
      return 'Password must be at least 8 characters.';
    case 'password_mismatch':
      return 'Passwords do not match.';
    case 'password_breached':
      return 'That password has appeared in a data breach. Please choose a different one.';
    case 'invalid_request':
      return 'Something went wrong. Please try again.';
    default:
      return 'An error occurred. Please try again.';
  }
}
