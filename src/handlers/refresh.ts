/**
 * Refresh Token Handler
 *
 * GET /api/refresh?tenant={tenantId}&redirect={returnUrl}
 *
 * Top-level redirect refresh flow per FD-4:
 * 1. Read HttpOnly refresh token cookie (SameSite=Lax works for top-level navigation)
 * 2. Validate redirect URL
 * 3. Look up token hash in D1
 * 4. If valid: rotate token (revoke old, issue new in same family)
 * 5. Issue new authorization code, redirect back with code
 * 6. If expired/invalid: redirect to login page
 * 7. If revoked token reused: revoke entire family (theft detection), redirect to login
 *
 * Security:
 * - Refresh token rotation with reuse/theft detection
 * - Redirect URL validated before redirect
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import {
  extractRefreshToken,
  generateRefreshToken,
  hashRefreshToken,
  generateAuthCode,
  hashAuthCode,
  generateUUID,
  buildRefreshCookieHeader,
  buildClearRefreshCookieHeader,
} from '../crypto/refreshTokens.js';
import { validateRedirectUrl } from '../security/redirectValidator.js';

/**
 * Handle GET /api/refresh
 *
 * Query params: tenant, redirect
 */
export async function handleRefresh(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const url = new URL(request.url);
  const tenantParam = url.searchParams.get('tenant') || '';
  const redirectUrl = url.searchParams.get('redirect') || '';
  const audienceParam = url.searchParams.get('audience') || '';

  // ── Validate redirect URL ──
  if (!redirectUrl) {
    return redirectToLogin(env, tenantParam, '', 'invalid_redirect');
  }

  const redirectValidation = await validateRedirectUrl(redirectUrl, env.TENANT_CONFIGS, env.ENVIRONMENT);
  if (!redirectValidation.valid) {
    return redirectToLogin(env, tenantParam, '', 'invalid_redirect');
  }

  // ── Extract refresh token from cookie ──
  const cookieHeader = request.headers.get('Cookie');
  const refreshTokenPlaintext = extractRefreshToken(cookieHeader);

  if (!refreshTokenPlaintext) {
    // No refresh token — redirect to login
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired');
  }

  // ── Look up token in D1 ──
  const tokenHash = await hashRefreshToken(refreshTokenPlaintext);
  const existingToken = await db.getRefreshTokenByHash(tokenHash);

  if (!existingToken) {
    // Token not found — redirect to login with cleared cookie
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired', true);
  }

  // ── Check if token was revoked (theft detection) ──
  if (existingToken.revoked_at !== null) {
    // REUSE DETECTED — revoke entire family
    console.error(
      `Refresh token reuse detected! Family=${existingToken.family_id}, User=${existingToken.user_id}`
    );
    await db.revokeRefreshTokenFamily(existingToken.family_id);
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired', true);
  }

  // ── Check expiration ──
  const now = Math.floor(Date.now() / 1000);
  if (existingToken.expires_at <= now) {
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired', true);
  }

  // ── Rotate token ──
  const newRefreshToken = generateRefreshToken();
  const newRefreshTokenHash = await hashRefreshToken(newRefreshToken);
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const newExpiresAt = Math.floor(Date.now() / 1000) + refreshTtlDays * 24 * 60 * 60;

  const rotationResult = await db.rotateRefreshToken(tokenHash, {
    id: generateUUID(),
    user_id: existingToken.user_id,
    token_hash: newRefreshTokenHash,
    family_id: existingToken.family_id,
    expires_at: newExpiresAt,
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'),
    user_agent: request.headers.get('User-Agent'),
  });

  if (!rotationResult.success) {
    if (rotationResult.reuseDetected) {
      console.error(
        `Refresh token reuse during rotation! Family=${existingToken.family_id}`
      );
    }
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired', true);
  }

  // ── Derive tenant ID ──
  const tenantId = redirectValidation.tenantId;

  // ── Generate authorization code ──
  const authCode = generateAuthCode();
  const authCodeHash = await hashAuthCode(authCode);
  const codeTtlSeconds = parseInt(env.AUTH_CODE_TTL_SECONDS || '60', 10);
  const codeExpiresAt = Math.floor(Date.now() / 1000) + codeTtlSeconds;

  // ── Determine audience (admin vs storefront) ──
  const aud = resolveAudience(redirectUrl, audienceParam);

  await db.insertAuthCode({
    code_hash: authCodeHash,
    user_id: existingToken.user_id,
    tenant_id: tenantId,
    redirect_origin: redirectValidation.origin,
    aud,
    expires_at: codeExpiresAt,
  });

  // ── Redirect back with code and new refresh cookie ──
  const returnUrl = new URL(redirectUrl);
  const callbackUrl = new URL('/auth/callback', returnUrl.origin);
  callbackUrl.searchParams.set('code', authCode);
  callbackUrl.searchParams.set('returnTo', returnUrl.pathname + returnUrl.search);

  const refreshCookie = buildRefreshCookieHeader(newRefreshToken, refreshTtlDays, env.AUTH_DOMAIN);

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
 * Redirect to login page with optional cookie clearing.
 */
function redirectToLogin(
  env: Env,
  tenant: string,
  redirect: string,
  error: string,
  clearCookie: boolean = false
): Response {
  const params = new URLSearchParams();
  if (tenant) params.set('tenant', tenant);
  if (redirect) params.set('redirect', redirect);
  params.set('error', error);

  const headers: Record<string, string> = {
    Location: `${env.AUTH_DOMAIN}/login?${params.toString()}`,
    'Cache-Control': 'no-store',
  };

  if (clearCookie) {
    headers['Set-Cookie'] = buildClearRefreshCookieHeader(env.AUTH_DOMAIN);
  }

  return new Response(null, {
    status: 302,
    headers,
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
