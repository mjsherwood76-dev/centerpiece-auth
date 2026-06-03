/**
 * Internal Customer Auth Endpoints (Phase 3.20 — Tenant Customer Inline Login)
 *
 * Service-Binding-only endpoints consumed by centerpiece-site-runtime so that
 * tenant storefronts can serve /login, /register, /forgot-password on their OWN
 * origin (no cross-domain redirect to the auth domain). Runtime proxies the
 * credential check here via the AUTH Service Binding; auth remains the sole
 * identity provider and the only writer of the `users` / `tenant_memberships` /
 * `refresh_tokens` tables.
 *
 *   POST /api/internal/customer-login            — verify password, issue tokens
 *   POST /api/internal/customer-register         — create user + customer membership
 *   POST /api/internal/customer-forgot-password  — send branded reset email
 *   POST /api/internal/customer-refresh          — rotate refresh + issue new access (Phase 3.20 S3)
 *   POST /api/internal/customer-logout           — revoke refresh server-side (Phase 3.20 S3)
 *
 * Contract (consumed by runtime S2/S3):
 *   Request bodies (JSON):
 *     login:    { email, password, tenantId, tenantOrigin }
 *     register: { email, password, tenantId, tenantOrigin, displayName? }
 *     forgot:   { email, tenantId, tenantOrigin }
 *     refresh:  { refreshToken, tenantId, tenantOrigin }
 *     logout:   { refreshToken }
 *   Success (login + register + refresh), 200:
 *     { accessToken, refreshToken, expiresIn, user: { id, email, displayName } }
 *   Failure:
 *     login    → 401 { error: 'invalid_credentials' }  (constant message)
 *     register → 409 { error: 'email_exists' }
 *     forgot   → 200 { ok: true }                       (unconditional)
 *     refresh  → 401 { error: 'invalid_refresh' }       (any rotation/theft/expiry failure)
 *     logout   → 200 { ok: true }                       (unconditional; idempotent)
 *
 * Refresh rotation + theft detection reuse the EXISTING D1 rotation primitives
 * (db.rotateRefreshToken / db.revokeRefreshTokenFamily) — the same machinery
 * the auth-domain silent-refresh flow uses. This endpoint is a thin Service-
 * Binding wrapper over them; rotation semantics are NOT reimplemented here.
 *
 * Security:
 * - Every endpoint is gated by X-CP-Internal-Secret (constant-time compare via
 *   requireInternalSecret) — the caller is a Worker, not a browser.
 * - `tenantOrigin` is validated server-side against the supplied `tenantId` via
 *   the read-only TENANTS_DB binding (redirect-validation discipline — tenantOrigin
 *   is a redirect-shaped parameter used for the reset-email link + audit logs).
 * - Memberships are auto-created ONLY with context `customer` (per auth AI_RULES);
 *   never seller/supplier/platform.
 * - Login failures return a constant `invalid_credentials` message regardless of
 *   whether the email or the password was wrong (account-enumeration prevention),
 *   with a dummy hash on the no-user path to keep timing consistent.
 * - Passwords are hashed/verified via the repo's existing PBKDF2-SHA-256 module
 *   (`crypto/passwords.ts`) — NOT argon2id.
 */
import type { Env } from '../types.js';
import { AuthDB, getTenantNames } from '../db.js';
import { hashPassword, verifyPassword } from '../crypto/passwords.js';
import { sha256Hex } from '../crypto/jwt.js';
import {
  signJwt,
  buildCustomerJwtPayload,
} from '../crypto/jwt.js';
import {
  generateRefreshToken,
  hashRefreshToken,
  generateAuthCode,
  generateUUID,
} from '../crypto/refreshTokens.js';
import { requireInternalSecret } from '../security/internalSecret.js';
import { buildDeviceLabel, buildDeviceFingerprint } from '../security/deviceLabel.js';
import { loadTenantBranding } from '../branding.js';
import { sendPasswordResetEmail } from '../email/send.js';
import { ConsoleJsonLogger } from '../core/logger.js';
import { logAuthEvent } from '../security/auditLog.js';
import { jsonResponse } from '../util/httpJson.js';

const logger = new ConsoleJsonLogger();

// ─── Types ──────────────────────────────────────────────────

interface CustomerLoginRequest {
  email?: string;
  password?: string;
  tenantId?: string;
  tenantOrigin?: string;
}

interface CustomerRegisterRequest extends CustomerLoginRequest {
  displayName?: string;
}

interface CustomerForgotRequest {
  email?: string;
  tenantId?: string;
  tenantOrigin?: string;
}

interface CustomerRefreshRequest {
  refreshToken?: string;
  tenantId?: string;
  tenantOrigin?: string;
}

interface CustomerLogoutRequest {
  refreshToken?: string;
}

/** Success body shared by login + register. S3 reads these to set cookies. */
interface CustomerAuthSuccess {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user: { id: string; email: string; displayName: string };
}

// ─── tenantOrigin validation ────────────────────────────────

/**
 * Validate that `tenantOrigin` is a well-formed https origin whose hostname
 * matches the domain registered for `tenantId` in TENANTS_DB.
 *
 * Returns the normalized origin on success, or null on any mismatch / malformed
 * input. Mirrors the redirect-validation discipline used by the auth-domain
 * login flow — tenantOrigin is a redirect-shaped parameter.
 */
async function validateTenantOrigin(
  env: Env,
  tenantId: string,
  tenantOrigin: string,
): Promise<string | null> {
  let url: URL;
  try {
    url = new URL(tenantOrigin);
  } catch {
    return null;
  }

  // Require https in production; allow http only for localhost in non-prod.
  const isDev = env.ENVIRONMENT !== 'production';
  const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(isDev && isLocalhost && url.protocol === 'http:')) {
    return null;
  }

  const names = await getTenantNames(env.TENANTS_DB, [tenantId]);
  const tenant = names.get(tenantId);
  if (!tenant) return null;

  // Domain match: the tenant's registered domain must equal the origin host.
  if (tenant.domain && tenant.domain.toLowerCase() === url.hostname.toLowerCase()) {
    return url.origin;
  }

  return null;
}

// ─── Token issuance ─────────────────────────────────────────

/**
 * Issue a customer access token (ES256 JWT, aud: storefront) plus a rotating
 * refresh token whose hash is persisted in `refresh_tokens`. The plaintext
 * refresh token is returned to the caller (runtime) which sets it as a cookie
 * in S3. This is the same token machinery as the auth-domain login flow; only
 * the delivery mechanism differs (direct return vs auth-code redirect).
 */
/**
 * Sign a customer access token (ES256 JWT, aud: storefront). Extracted so the
 * refresh endpoint can mint a fresh access token on rotation without duplicating
 * the claim factory. The claim shape is identical to the auth-domain customer
 * token — the runtime's existing JWKS verifier reads it unchanged (S3 step 4).
 */
async function signCustomerAccessToken(
  env: Env,
  user: { id: string; email: string; name: string },
  ttlSeconds: number,
): Promise<string> {
  return signJwt(
    buildCustomerJwtPayload({
      userId: user.id,
      email: user.email,
      name: user.name || '',
      iss: env.AUTH_DOMAIN,
    }),
    env.JWT_PRIVATE_KEY,
    ttlSeconds,
  );
}

async function issueCustomerTokens(
  request: Request,
  env: Env,
  user: { id: string; email: string; name: string },
): Promise<CustomerAuthSuccess> {
  const ttlSeconds = parseInt(env.ACCESS_TOKEN_TTL_SECONDS || '900', 10);

  const accessToken = await signCustomerAccessToken(env, user, ttlSeconds);

  const refreshToken = generateRefreshToken();
  const refreshTokenHash = await hashRefreshToken(refreshToken);
  const loginIat = Math.floor(Date.now() / 1000);
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const refreshExpiresAt = loginIat + refreshTtlDays * 24 * 60 * 60;

  const db = new AuthDB(env.AUTH_DB);
  const ua = request.headers.get('User-Agent');
  const cfCountry = request.headers.get('CF-IPCountry');

  await db.insertRefreshToken({
    id: generateUUID(),
    user_id: user.id,
    token_hash: refreshTokenHash,
    family_id: generateUUID(),
    expires_at: refreshExpiresAt,
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'),
    user_agent: ua,
    device_remembered: 0,
    device_label: buildDeviceLabel(ua),
    device_fingerprint: await buildDeviceFingerprint(ua, cfCountry),
    login_iat: loginIat,
  });

  return {
    accessToken,
    refreshToken,
    expiresIn: ttlSeconds,
    user: { id: user.id, email: user.email, displayName: user.name || '' },
  };
}

/**
 * Dummy PBKDF2 work to keep timing consistent on the no-user / no-password
 * login paths (account-enumeration prevention). Mirrors handlers/login.ts.
 */
async function dummyHashDelay(): Promise<void> {
  const dummyKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('dummy-password'),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new Uint8Array(32), iterations: 100_000, hash: 'SHA-256' },
    dummyKey,
    256,
  );
}

function auditIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')
    || 'internal';
}

function correlationOf(request: Request): string {
  return request.headers.get('x-correlation-id')
    || request.headers.get('x-request-id')
    || 'unknown';
}

// ─── POST /api/internal/customer-login ──────────────────────

async function handleCustomerLogin(request: Request, env: Env): Promise<Response> {
  let body: CustomerLoginRequest;
  try {
    body = await request.json() as CustomerLoginRequest;
  } catch {
    return jsonResponse({ error: 'invalid_request' }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  const tenantId = (body.tenantId || '').trim();
  const tenantOrigin = (body.tenantOrigin || '').trim();

  if (!tenantId || !tenantOrigin) {
    return jsonResponse({ error: 'invalid_request' }, 400);
  }

  const validOrigin = await validateTenantOrigin(env, tenantId, tenantOrigin);
  if (!validOrigin) {
    return jsonResponse({ error: 'invalid_tenant_origin' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const user = email ? await db.getUserByEmail(email) : null;

  // Constant message + constant timing for all credential failures.
  if (!user || !user.password_hash) {
    await dummyHashDelay();
    return jsonResponse({ error: 'invalid_credentials' }, 401);
  }

  const passwordValid = await verifyPassword(password, user.password_hash);
  if (!passwordValid) {
    return jsonResponse({ error: 'invalid_credentials' }, 401);
  }

  // Auto-create the customer membership (context 'customer' only — never
  // seller/supplier/platform). ensureMembership is idempotent and hard-codes
  // the customer context.
  await db.ensureMembership(generateUUID(), user.id, tenantId);

  const success = await issueCustomerTokens(request, env, {
    id: user.id,
    email: user.email,
    name: user.name,
  });

  logAuthEvent(logger, {
    event: 'customer_login_inline',
    ip: auditIp(request),
    route: '/api/internal/customer-login',
    userAgent: request.headers.get('User-Agent'),
    userId: user.id,
    statusCode: 200,
    correlationId: correlationOf(request),
    details: { tenantId, tenantOrigin: validOrigin },
  });

  return jsonResponse(success, 200);
}

// ─── POST /api/internal/customer-register ───────────────────

async function handleCustomerRegister(request: Request, env: Env): Promise<Response> {
  let body: CustomerRegisterRequest;
  try {
    body = await request.json() as CustomerRegisterRequest;
  } catch {
    return jsonResponse({ error: 'invalid_request' }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  const tenantId = (body.tenantId || '').trim();
  const tenantOrigin = (body.tenantOrigin || '').trim();
  let displayName = (body.displayName || '').trim();

  if (!tenantId || !tenantOrigin) {
    return jsonResponse({ error: 'invalid_request' }, 400);
  }
  if (!email || !isValidEmail(email)) {
    return jsonResponse({ error: 'invalid_email' }, 400);
  }
  if (password.length < 8) {
    return jsonResponse({ error: 'password_weak' }, 400);
  }

  const validOrigin = await validateTenantOrigin(env, tenantId, tenantOrigin);
  if (!validOrigin) {
    return jsonResponse({ error: 'invalid_tenant_origin' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // Registration inherently reveals whether an email exists (account-enumeration
  // is unavoidable for registration UX; mitigated by Phase 3.12 rate limiting).
  const existing = await db.getUserByEmail(email);
  if (existing) {
    return jsonResponse({ error: 'email_exists' }, 409);
  }

  if (!displayName) {
    displayName = email.split('@')[0];
  }

  const userId = generateUUID();
  const passwordHash = await hashPassword(password);
  await db.insertUser({
    id: userId,
    email,
    password_hash: passwordHash,
    name: displayName,
    email_verified: false,
  });

  // Customer membership only.
  await db.ensureMembership(generateUUID(), userId, tenantId);

  const success = await issueCustomerTokens(request, env, {
    id: userId,
    email,
    name: displayName,
  });

  logAuthEvent(logger, {
    event: 'customer_login_inline',
    ip: auditIp(request),
    route: '/api/internal/customer-register',
    userAgent: request.headers.get('User-Agent'),
    userId,
    statusCode: 200,
    correlationId: correlationOf(request),
    details: { tenantId, tenantOrigin: validOrigin, registered: true },
  });

  return jsonResponse(success, 200);
}

// ─── POST /api/internal/customer-forgot-password ────────────

async function handleCustomerForgotPassword(request: Request, env: Env): Promise<Response> {
  let body: CustomerForgotRequest;
  try {
    body = await request.json() as CustomerForgotRequest;
  } catch {
    // Even malformed bodies get the constant success response.
    return jsonResponse({ ok: true }, 200);
  }

  const email = (body.email || '').trim().toLowerCase();
  const tenantId = (body.tenantId || '').trim();
  const tenantOrigin = (body.tenantOrigin || '').trim();

  // tenantOrigin must validate before we send any tenant-branded email, but a
  // failure must NOT leak through the response (constant { ok: true }).
  const validOrigin = (tenantId && tenantOrigin)
    ? await validateTenantOrigin(env, tenantId, tenantOrigin)
    : null;

  if (email && validOrigin) {
    const db = new AuthDB(env.AUTH_DB);
    await db.enableForeignKeys();

    const user = await db.getUserByEmail(email);
    if (user) {
      const resetToken = generateAuthCode();
      const resetTokenHash = await sha256Hex(resetToken);
      const expiresAt = Math.floor(Date.now() / 1000) + 3600; // 1-hour TTL

      await db.insertPasswordResetToken({
        token_hash: resetTokenHash,
        user_id: user.id,
        expires_at: expiresAt,
      });

      // Reset link lands on the TENANT origin (inline-login lives there), not
      // the auth domain. The reset-completion page is delivered in a later
      // phase; for S1 the link target is the validated tenant origin.
      const resetUrl = `${validOrigin}/reset-password?token=${resetToken}`;
      const branding = await loadTenantBranding(tenantId, env);
      await sendPasswordResetEmail(env, user.email, resetUrl, branding, {
        tenantId,
        userId: user.id,
      });
    }
  }

  // Always the same response — never reveal email existence (account-enumeration
  // prevention per AI_RULES).
  return jsonResponse({ ok: true }, 200);
}

// ─── POST /api/internal/customer-refresh ────────────────────

/**
 * Rotate a customer refresh token and mint a fresh access token.
 *
 * Reuses the existing rotation primitives (db.getRefreshTokenByHash +
 * db.rotateRefreshToken) which implement reuse/theft detection identically to
 * the auth-domain silent-refresh flow:
 *  - revoked token presented again → entire family revoked → 401 invalid_refresh
 *  - expired token                  → 401 invalid_refresh
 *  - not found                      → 401 invalid_refresh
 *
 * On success returns the same body shape as login (new access + new refresh).
 * The runtime (S3) overwrites both cookies with the rotated values.
 *
 * Any failure collapses to a constant 401 { error: 'invalid_refresh' } — the
 * caller never learns WHY (no-session vs expired vs theft) over the wire.
 */
async function handleCustomerRefresh(request: Request, env: Env): Promise<Response> {
  let body: CustomerRefreshRequest;
  try {
    body = await request.json() as CustomerRefreshRequest;
  } catch {
    return jsonResponse({ error: 'invalid_request' }, 400);
  }

  const refreshToken = (body.refreshToken || '').trim();
  const tenantId = (body.tenantId || '').trim();
  const tenantOrigin = (body.tenantOrigin || '').trim();

  if (!refreshToken || !tenantId || !tenantOrigin) {
    return jsonResponse({ error: 'invalid_request' }, 400);
  }

  const validOrigin = await validateTenantOrigin(env, tenantId, tenantOrigin);
  if (!validOrigin) {
    return jsonResponse({ error: 'invalid_tenant_origin' }, 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const tokenHash = await hashRefreshToken(refreshToken);
  const existing = await db.getRefreshTokenByHash(tokenHash);

  if (!existing) {
    return jsonResponse({ error: 'invalid_refresh' }, 401);
  }

  // Theft detection: a revoked token presented again revokes the whole family.
  if (existing.revoked_at !== null) {
    await db.revokeRefreshTokenFamily(existing.family_id);
    logAuthEvent(logger, {
      event: 'customer_refresh_reuse_detected',
      ip: auditIp(request),
      route: '/api/internal/customer-refresh',
      userAgent: request.headers.get('User-Agent'),
      userId: existing.user_id,
      statusCode: 401,
      correlationId: correlationOf(request),
      details: { tenantId, familyId: existing.family_id },
    });
    return jsonResponse({ error: 'invalid_refresh' }, 401);
  }

  const now = Math.floor(Date.now() / 1000);
  if (existing.expires_at <= now) {
    return jsonResponse({ error: 'invalid_refresh' }, 401);
  }

  const user = await db.getUserById(existing.user_id);
  if (!user) {
    return jsonResponse({ error: 'invalid_refresh' }, 401);
  }

  // Rotate: revoke old, issue new in the same family. login_iat is carried
  // forward by the DB primitive. reuseDetected can race here too.
  const newRefreshToken = generateRefreshToken();
  const newRefreshTokenHash = await hashRefreshToken(newRefreshToken);
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const newExpiresAt = now + refreshTtlDays * 24 * 60 * 60;

  const rotation = await db.rotateRefreshToken(tokenHash, {
    id: generateUUID(),
    user_id: existing.user_id,
    token_hash: newRefreshTokenHash,
    family_id: existing.family_id,
    expires_at: newExpiresAt,
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'),
    user_agent: request.headers.get('User-Agent'),
  });

  if (!rotation.success) {
    return jsonResponse({ error: 'invalid_refresh' }, 401);
  }

  const ttlSeconds = parseInt(env.ACCESS_TOKEN_TTL_SECONDS || '900', 10);
  const accessToken = await signCustomerAccessToken(
    env,
    { id: user.id, email: user.email, name: user.name },
    ttlSeconds,
  );

  const success: CustomerAuthSuccess = {
    accessToken,
    refreshToken: newRefreshToken,
    expiresIn: ttlSeconds,
    user: { id: user.id, email: user.email, displayName: user.name || '' },
  };

  logAuthEvent(logger, {
    event: 'customer_refresh_inline',
    ip: auditIp(request),
    route: '/api/internal/customer-refresh',
    userAgent: request.headers.get('User-Agent'),
    userId: user.id,
    statusCode: 200,
    correlationId: correlationOf(request),
    details: { tenantId },
  });

  return jsonResponse(success, 200);
}

// ─── POST /api/internal/customer-logout ─────────────────────

/**
 * Revoke a customer refresh token server-side (single session). Idempotent —
 * an unknown/missing token still returns { ok: true } so the runtime can always
 * clear cookies and redirect home without leaking whether the token was live.
 *
 * Reuses db.revokeRefreshToken (the same single-session revoke path the
 * auth-domain logout uses). No tenantOrigin check is required — possession of a
 * valid internal secret + the plaintext refresh token is sufficient, and
 * revoking a token is never harmful.
 */
async function handleCustomerLogout(request: Request, env: Env): Promise<Response> {
  let body: CustomerLogoutRequest;
  try {
    body = await request.json() as CustomerLogoutRequest;
  } catch {
    return jsonResponse({ ok: true }, 200);
  }

  const refreshToken = (body.refreshToken || '').trim();
  if (refreshToken) {
    const db = new AuthDB(env.AUTH_DB);
    await db.enableForeignKeys();
    const tokenHash = await hashRefreshToken(refreshToken);
    await db.revokeRefreshToken(tokenHash);
  }

  logAuthEvent(logger, {
    event: 'customer_logout_inline',
    ip: auditIp(request),
    route: '/api/internal/customer-logout',
    userAgent: request.headers.get('User-Agent'),
    statusCode: 200,
    correlationId: correlationOf(request),
  });

  return jsonResponse({ ok: true }, 200);
}

// ─── Unified Router ─────────────────────────────────────────

/**
 * Route handler for /api/internal/customer-* endpoints.
 * Validates the internal secret, then dispatches by method + path.
 */
export async function handleInternalCustomerAuth(request: Request, env: Env): Promise<Response> {
  const denied = requireInternalSecret(request, env);
  if (denied) return denied;

  const method = request.method;
  const path = new URL(request.url).pathname;

  if (method === 'POST' && path === '/api/internal/customer-login') {
    return handleCustomerLogin(request, env);
  }
  if (method === 'POST' && path === '/api/internal/customer-register') {
    return handleCustomerRegister(request, env);
  }
  if (method === 'POST' && path === '/api/internal/customer-forgot-password') {
    return handleCustomerForgotPassword(request, env);
  }
  if (method === 'POST' && path === '/api/internal/customer-refresh') {
    return handleCustomerRefresh(request, env);
  }
  if (method === 'POST' && path === '/api/internal/customer-logout') {
    return handleCustomerLogout(request, env);
  }

  return jsonResponse({ error: 'Not found' }, 404);
}

// ─── Helpers ────────────────────────────────────────────────

function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}
