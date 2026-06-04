/**
 * Registration Handler
 *
 * POST /api/register — Email/password registration
 *
 * Flow:
 * 1. Parse and validate inputs (email, password, name, tenant, redirect)
 * 2. Validate redirect URL via redirectValidator
 * 3. Check for existing user by email
 * 4. Hash password, insert into `users` table
 * 5. Create `tenant_memberships` row with role `customer` only
 * 6. Issue refresh token cookie on auth domain
 * 7. Generate one-time authorization code → store hash in `auth_codes`
 * 8. Redirect to `{returnUrl}?code={authorizationCode}`
 *
 * Security:
 * - Password strength ≥ 8 chars
 * - Role always `customer` (never auto-create seller/admin)
 * - Redirect URL validated before any auth processing
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { hashPassword } from '../crypto/passwords.js';
import { sha256Hex } from '../crypto/jwt.js';
import {
  generateRefreshToken,
  hashRefreshToken,
  generateAuthCode,
  hashAuthCode,
  generateUUID,
  buildRefreshCookieHeader,
} from '../crypto/refreshTokens.js';
import { validateRedirectUrl } from '../security/redirectValidator.js';
import { isAdminDomain } from '../security/platformDomains.js';
import { loadTenantBranding } from '../branding.js';
import { sendWelcomeEmail } from '../email/send.js';
import { maybeSendVerificationForGatedTenant } from './emailVerification.js';
import { parseRequestBody } from '../util/parseRequestBody.js';
import { buildDeviceLabel, buildDeviceFingerprint } from '../security/deviceLabel.js';
import { loadTenantGating } from '../security/tenantGating.js';
import { isEmailAllowedForTenant } from '../security/emailDomainCheck.js';
import { ConsoleJsonLogger } from '../core/logger.js';
import { logAuthEvent } from '../security/auditLog.js';

const logger = new ConsoleJsonLogger();

/**
 * Handle POST /api/register
 *
 * Accepts form-urlencoded body (from the register page form):
 *   email, password, confirmPassword, name, tenant, redirect, audience?, code_challenge?
 */
export async function handleRegister(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Parse form body ──
  let email: string;
  let password: string;
  let confirmPassword: string;
  let name: string;
  let tenantParam: string;
  let redirectUrl: string;
  let audienceParam: string;
  let codeChallenge: string;
  let pkceSession: string;
  let rememberDevice: boolean;

  try {
    const body = await parseRequestBody(request);

    email = (body.email || '').trim().toLowerCase();
    password = body.password || '';
    confirmPassword = body.confirmPassword || '';
    name = (body.name || '').trim();
    tenantParam = (body.tenant || '').trim();
    redirectUrl = (body.redirect || '').trim();
    audienceParam = (body.audience || '').trim();
    codeChallenge = (body.code_challenge || '').trim();
    pkceSession = (body.pkce_session || '').trim();
    rememberDevice = body.remember_device === '1' || body.remember_device === 'true';
  } catch {
    return errorRedirect(env, '', '', 'invalid_request');
  }

  // ── Validate redirect URL first (security boundary) ──
  if (!redirectUrl) {
    return errorRedirect(env, tenantParam, '', 'invalid_redirect');
  }

  const redirectValidation = await validateRedirectUrl(redirectUrl, env.TENANT_CONFIGS, env.ENVIRONMENT);
  if (!redirectValidation.valid) {
    return errorRedirect(env, tenantParam, '', 'invalid_redirect');
  }

  // ── Validate inputs ──
  if (!email || !isValidEmail(email)) {
    return errorRedirect(env, tenantParam, redirectUrl, 'invalid_email');
  }

  if (password.length < 8) {
    return errorRedirect(env, tenantParam, redirectUrl, 'password_weak');
  }

  if (password !== confirmPassword) {
    return errorRedirect(env, tenantParam, redirectUrl, 'password_mismatch');
  }

  if (!name) {
    name = email.split('@')[0]; // Fallback: use email prefix as name
  }

  // ── Derive tenant ID ──
  // Authoritative tenant comes from the redirect URL, not the client-provided param
  const tenantId = redirectValidation.tenantId;

  // If tenant param is provided, verify it matches (or ignore mismatch for branding)
  // Per security rules: tenant param is a branding hint only

  // ── Check for existing user ──
  const existingUser = await db.getUserByEmail(email);
  if (existingUser) {
    return errorRedirect(env, tenantParam, redirectUrl, 'email_exists');
  }

  // ── Gated-tenant domain allowlist (Phase 3.25) ──
  // On a gated tenant, only emails whose domain is on the tenant's allowlist may
  // register. Public (ungated) tenants are unaffected (loadTenantGating returns
  // ungated). The rejection message does NOT echo the allowed domains.
  const gating = await loadTenantGating(env, tenantId || null);
  if (gating.gated && gating.policy === 'domain-allowlist'
      && !isEmailAllowedForTenant(email, gating.allowedEmailDomains)) {
    logAuthEvent(logger, {
      event: 'customer_domain_restricted',
      ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown',
      route: '/api/register',
      userAgent: request.headers.get('User-Agent'),
      statusCode: 302,
      correlationId: request.headers.get('x-correlation-id') || 'unknown',
      details: { tenantId, emailDomain: redactEmailDomain(email) },
    });
    return errorRedirect(env, tenantParam, redirectUrl, 'domain_not_allowed');
  }

  // ── Create user ──
  const userId = generateUUID();
  const passwordHash = await hashPassword(password);

  await db.insertUser({
    id: userId,
    email,
    password_hash: passwordHash,
    name,
    email_verified: false,
  });

  // ── Create tenant membership (customer only — per security rules) ──
  const membershipId = generateUUID();
  await db.ensureMembership(membershipId, userId, tenantId);

  // ── Gated-tenant email verification (Phase 3.25, non-blocking) ──
  // On a gated tenant, send a one-time verification link; email_verified stays
  // false until the link is used. No-op on ungated tenants.
  if (tenantId) {
    await maybeSendVerificationForGatedTenant(env, db, tenantId, { id: userId, email });
  }

  // ── Send welcome email (non-blocking) ──
  const branding = await loadTenantBranding(tenantParam || null, env);
  const loginUrl = `${env.AUTH_DOMAIN}/login?tenant=${encodeURIComponent(tenantParam)}`;
  await sendWelcomeEmail(env, email, name, loginUrl, branding, {
    tenantId: tenantId || undefined,
    userId,
  });

  // ── Issue refresh token ──
  const refreshToken = generateRefreshToken();
  const refreshTokenHash = await hashRefreshToken(refreshToken);
  const familyId = generateUUID();
  const refreshTokenId = generateUUID();
  const loginIat = Math.floor(Date.now() / 1000);
  const refreshTtlDays = rememberDevice
    ? parseInt(env.REFRESH_TOKEN_TTL_DAYS_REMEMBERED || '90', 10)
    : parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const refreshExpiresAt = loginIat + refreshTtlDays * 24 * 60 * 60;

  const ua = request.headers.get('User-Agent');
  const cfCountry = request.headers.get('CF-IPCountry');

  await db.insertRefreshToken({
    id: refreshTokenId,
    user_id: userId,
    token_hash: refreshTokenHash,
    family_id: familyId,
    expires_at: refreshExpiresAt,
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'),
    user_agent: ua,
    device_remembered: rememberDevice ? 1 : 0,
    device_label: buildDeviceLabel(ua),
    device_fingerprint: await buildDeviceFingerprint(ua, cfCountry),
    login_iat: loginIat,
  });

  // ── Generate authorization code ──
  const authCode = generateAuthCode();
  const authCodeHash = await hashAuthCode(authCode);
  const codeTtlSeconds = parseInt(env.AUTH_CODE_TTL_SECONDS || '60', 10);
  const codeExpiresAt = loginIat + codeTtlSeconds;

  // ── Determine audience (admin vs storefront) ──
  const aud = resolveAudience(redirectUrl, audienceParam);

  await db.insertAuthCode({
    code_hash: authCodeHash,
    user_id: userId,
    tenant_id: tenantId,
    redirect_origin: redirectValidation.origin,
    aud,
    expires_at: codeExpiresAt,
    code_challenge: aud === 'admin' && codeChallenge ? codeChallenge : null,
    code_challenge_method: aud === 'admin' && codeChallenge ? 'S256' : null,
    refresh_token_id: refreshTokenId,
  });

  // ── Redirect with code ──
  const returnUrl = new URL(redirectUrl);
  // Replace the path to the auth callback on the tenant domain
  const callbackUrl = new URL('/auth/callback', returnUrl.origin);
  callbackUrl.searchParams.set('code', authCode);
  // Preserve original path as the final redirect destination
  callbackUrl.searchParams.set('returnTo', returnUrl.pathname + returnUrl.search);
  // Carry the server-side PKCE session reference back to the SPA so the eventual
  // /api/token call can resolve the verifier without depending on client storage.
  if (aud === 'admin' && pkceSession) {
    callbackUrl.searchParams.set('pkce_session_id', pkceSession);
  }

  const refreshCookie = buildRefreshCookieHeader(refreshToken, refreshTtlDays, env.AUTH_DOMAIN);

  return new Response(null, {
    status: 302,
    headers: {
      Location: callbackUrl.toString(),
      'Set-Cookie': refreshCookie,
      'Cache-Control': 'no-store',
    },
  });
}

// ─── Helpers ────────────────────────────────────────────────

/**
 * Extract the bare domain from an email for audit logging. The local part is PII
 * and is never logged; the domain alone identifies WHICH allowlist rejected the
 * attempt without exposing the person.
 */
function redactEmailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1).toLowerCase() : 'unknown';
}

/**
 * Basic email validation.
 */
function isValidEmail(email: string): boolean {
  // Simple validation: must have @ with content before and after, and a dot in the domain
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Redirect back to the register page with an error code.
 */
function errorRedirect(env: Env, tenant: string, redirect: string, error: string): Response {
  const params = new URLSearchParams();
  if (tenant) params.set('tenant', tenant);
  if (redirect) params.set('redirect', redirect);
  params.set('error', error);

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.AUTH_DOMAIN}/register?${params.toString()}`,
      'Cache-Control': 'no-store',
    },
  });
}

/**
 * Determine whether the auth flow is for the admin SPA or the storefront.
 */
function resolveAudience(
  redirectUrl: string,
  audienceParam: string
): 'storefront' | 'admin' {
  if (audienceParam === 'admin') return 'admin';
  try {
    const hostname = new URL(redirectUrl).hostname;
    if (isAdminDomain(hostname)) return 'admin';
  } catch {
    // Invalid URL — fall through to storefront
  }
  return 'storefront';
}
