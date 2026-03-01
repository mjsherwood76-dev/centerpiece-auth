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
import { loadTenantBranding } from '../branding.js';
import { sendWelcomeEmail } from '../email/send.js';

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

  try {
    const contentType = request.headers.get('Content-Type') || '';
    let body: Record<string, string>;

    if (contentType.includes('application/json')) {
      body = await request.json() as Record<string, string>;
    } else {
      // application/x-www-form-urlencoded (default form submission)
      const formData = await request.formData();
      body = {} as Record<string, string>;
      formData.forEach((value, key) => {
        if (typeof value === 'string') body[key] = value;
      });
    }

    email = (body.email || '').trim().toLowerCase();
    password = body.password || '';
    confirmPassword = body.confirmPassword || '';
    name = (body.name || '').trim();
    tenantParam = (body.tenant || '').trim();
    redirectUrl = (body.redirect || '').trim();
    audienceParam = (body.audience || '').trim();
    codeChallenge = (body.code_challenge || '').trim();
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
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + refreshTtlDays * 24 * 60 * 60;

  await db.insertRefreshToken({
    id: generateUUID(),
    user_id: userId,
    token_hash: refreshTokenHash,
    family_id: familyId,
    expires_at: refreshExpiresAt,
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'),
    user_agent: request.headers.get('User-Agent'),
  });

  // ── Generate authorization code ──
  const authCode = generateAuthCode();
  const authCodeHash = await hashAuthCode(authCode);
  const codeTtlSeconds = parseInt(env.AUTH_CODE_TTL_SECONDS || '60', 10);
  const codeExpiresAt = Math.floor(Date.now() / 1000) + codeTtlSeconds;

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
  });

  // ── Redirect with code ──
  const returnUrl = new URL(redirectUrl);
  // Replace the path to the auth callback on the tenant domain
  const callbackUrl = new URL('/auth/callback', returnUrl.origin);
  callbackUrl.searchParams.set('code', authCode);
  // Preserve original path as the final redirect destination
  callbackUrl.searchParams.set('returnTo', returnUrl.pathname + returnUrl.search);

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

/** Admin domain patterns for audience determination. */
const ADMIN_DOMAINS = [
  'admin.centerpiecelab.com',
  'centerpiece-admin-staging.pages.dev',
];

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
    if (ADMIN_DOMAINS.includes(hostname)) return 'admin';
  } catch {
    // Invalid URL — fall through to storefront
  }
  return 'storefront';
}
