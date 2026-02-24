/**
 * Login Handler
 *
 * POST /api/login — Email/password login
 *
 * Flow:
 * 1. Parse and validate inputs (email, password, tenant, redirect)
 * 2. Validate redirect URL via redirectValidator
 * 3. Lookup user by email, verify password hash
 * 4. Constant-time comparison to prevent timing attacks
 * 5. Account enumeration prevention: always "Invalid email or password"
 * 6. Ensure tenant membership (customer only)
 * 7. Issue refresh token + authorization code
 * 8. Redirect with authorization code
 *
 * Security:
 * - Generic error message for both wrong email and wrong password
 * - Redirect URL validated before any auth processing
 * - Constant-time password comparison (in verifyPassword)
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { verifyPassword } from '../crypto/passwords.js';
import {
  generateRefreshToken,
  hashRefreshToken,
  generateAuthCode,
  hashAuthCode,
  generateUUID,
  buildRefreshCookieHeader,
} from '../crypto/refreshTokens.js';
import { validateRedirectUrl } from '../security/redirectValidator.js';

/**
 * Handle POST /api/login
 *
 * Accepts form-urlencoded body (from the login page form):
 *   email, password, tenant, redirect
 */
export async function handleLogin(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Parse form body ──
  let email: string;
  let password: string;
  let tenantParam: string;
  let redirectUrl: string;

  try {
    const contentType = request.headers.get('Content-Type') || '';
    let body: Record<string, string>;

    if (contentType.includes('application/json')) {
      body = await request.json() as Record<string, string>;
    } else {
      const formData = await request.formData();
      body = {} as Record<string, string>;
      formData.forEach((value, key) => {
        if (typeof value === 'string') body[key] = value;
      });
    }

    email = (body.email || '').trim().toLowerCase();
    password = body.password || '';
    tenantParam = (body.tenant || '').trim();
    redirectUrl = (body.redirect || '').trim();
  } catch {
    return errorRedirect(env, '', '', 'invalid_credentials');
  }

  // ── Validate redirect URL first (security boundary) ──
  if (!redirectUrl) {
    return errorRedirect(env, tenantParam, '', 'invalid_redirect');
  }

  const redirectValidation = await validateRedirectUrl(redirectUrl, env.TENANT_CONFIGS, env.ENVIRONMENT);
  if (!redirectValidation.valid) {
    return errorRedirect(env, tenantParam, '', 'invalid_redirect');
  }

  // ── Validate email format ──
  if (!email) {
    return errorRedirect(env, tenantParam, redirectUrl, 'invalid_credentials');
  }

  // ── Lookup user by email ──
  const user = await db.getUserByEmail(email);

  if (!user) {
    // Account enumeration prevention: same error for missing user
    // Do a dummy hash to keep timing consistent
    await dummyHashDelay();
    return errorRedirect(env, tenantParam, redirectUrl, 'invalid_credentials');
  }

  // ── Verify password ──
  if (!user.password_hash) {
    // User exists but has no password (OAuth-only account)
    // Same generic error to prevent enumeration
    await dummyHashDelay();
    return errorRedirect(env, tenantParam, redirectUrl, 'invalid_credentials');
  }

  const passwordValid = await verifyPassword(password, user.password_hash);
  if (!passwordValid) {
    return errorRedirect(env, tenantParam, redirectUrl, 'invalid_credentials');
  }

  // ── Derive tenant ID from redirect URL ──
  const tenantId = redirectValidation.tenantId;

  // ── Ensure tenant membership (customer only — per security rules) ──
  const membershipId = generateUUID();
  await db.ensureMembership(membershipId, user.id, tenantId);

  // ── Issue refresh token ──
  const refreshToken = generateRefreshToken();
  const refreshTokenHash = await hashRefreshToken(refreshToken);
  const familyId = generateUUID();
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + refreshTtlDays * 24 * 60 * 60;

  await db.insertRefreshToken({
    id: generateUUID(),
    user_id: user.id,
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

  await db.insertAuthCode({
    code_hash: authCodeHash,
    user_id: user.id,
    tenant_id: tenantId,
    redirect_origin: redirectValidation.origin,
    aud: 'storefront',
    expires_at: codeExpiresAt,
  });

  // ── Redirect with code ──
  const returnUrl = new URL(redirectUrl);
  const callbackUrl = new URL('/auth/callback', returnUrl.origin);
  callbackUrl.searchParams.set('code', authCode);
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
 * Perform a dummy PBKDF2 hash to make timing consistent
 * whether a user exists or not. Prevents timing-based
 * account enumeration.
 */
async function dummyHashDelay(): Promise<void> {
  const dummyKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('dummy-password'),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(32),
      iterations: 100_000,
      hash: 'SHA-256',
    },
    dummyKey,
    256
  );
}

/**
 * Redirect back to the login page with an error code.
 */
function errorRedirect(env: Env, tenant: string, redirect: string, error: string): Response {
  const params = new URLSearchParams();
  if (tenant) params.set('tenant', tenant);
  if (redirect) params.set('redirect', redirect);
  params.set('error', error);

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.AUTH_DOMAIN}/login?${params.toString()}`,
      'Cache-Control': 'no-store',
    },
  });
}
