/**
 * Refresh Token Handler
 *
 * GET /api/refresh?tenant={tenantId}&redirect={returnUrl}[&silent=1][&audience=admin]
 *
 * Top-level redirect refresh flow per FD-4:
 * 1. Read HttpOnly refresh token cookie
 * 2. Validate redirect URL
 * 3. Look up token hash in D1
 * 4. If valid: rotate token (revoke old, issue new in same family)
 * 5. Issue new authorization code, redirect back with code
 * 6. If expired/invalid: redirect to login page
 * 7. If revoked token reused: revoke entire family (theft detection), redirect to login
 *
 * Silent refresh mode (silent=1):
 * When ?silent=1 is present the caller is a hidden iframe spawned by the admin SPA.
 * Instead of 302 redirects, every path returns an HTML page that calls
 * parent.postMessage({type:'cp-auth-silent-refresh', code|error}, adminOrigin).
 * The admin SPA listens for the message and either exchanges the code for a JWT
 * (success) or falls through to a top-level login redirect (failure).
 *
 * Security:
 * - Refresh token rotation with reuse/theft detection
 * - Redirect URL validated before any redirect
 * - admin origin derived from redirect URL, validated via isAdminDomain
 * - postMessage HTML uses data-attribute payload (no inline JS interpolation)
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
import { isAdminDomain } from '../security/platformDomains.js';

// ─── HTML attribute escaper (used in silent refresh HTML) ────

/**
 * Escape a string for safe use as an HTML attribute value (single-quoted).
 * Covers the five characters that must be escaped in any HTML attribute context.
 */
function escapeHtmlAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/'/g, '&#39;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ─── Silent refresh HTML renderer ───────────────────────────

/**
 * Render an HTML page that posts a message to the parent frame.
 *
 * The auth code (or error reason) is transported via a `data-payload` attribute
 * rather than interpolated directly into a script literal. This means the JSON
 * string is HTML-attribute-escaped but never injected as raw JS — no XSS vector
 * even if an attacker could influence the code or error values.
 *
 * Auth codes are 64-char hex (safe). Error strings are hardcoded in this module
 * (safe). The admin origin is validated via isAdminDomain before this function
 * is called (safe).
 *
 * @param message - Object to post (must be JSON-serialisable)
 * @param adminOrigin - Target origin for postMessage (e.g. https://hub.centerpiecelab.com)
 */
function renderSilentRefreshResponse(
  message: Record<string, string>,
  adminOrigin: string
): Response {
  const payloadJson = JSON.stringify(message);
  const escapedPayload = escapeHtmlAttr(payloadJson);
  const escapedOrigin = escapeHtmlAttr(adminOrigin);

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<div id="cp-payload" data-payload='${escapedPayload}'></div>
<script>
(function(){
  var el=document.getElementById('cp-payload');
  try{parent.postMessage(JSON.parse(el.dataset.payload),'${escapedOrigin}');}catch(e){}
})();
</script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'ALLOWALL',
    },
  });
}

/**
 * Handle GET /api/refresh
 *
 * Query params: tenant, redirect, [silent], [audience]
 */
export async function handleRefresh(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const url = new URL(request.url);
  const tenantParam = url.searchParams.get('tenant') || '';
  const redirectUrl = url.searchParams.get('redirect') || '';
  const audienceParam = url.searchParams.get('audience') || '';
  const silent = url.searchParams.get('silent') === '1';

  // ── Derive admin origin for silent mode (validated later after redirect check) ──
  // We compute it here so failure paths can use it; we only trust it after
  // isAdminDomain confirms the redirect URL points to an admin hostname.
  let adminOrigin = '';

  // ── Validate redirect URL ──
  if (!redirectUrl) {
    if (silent) {
      return renderSilentRefreshResponse(
        { type: 'cp-auth-silent-refresh', error: 'no_session' },
        adminOrigin
      );
    }
    return redirectToLogin(env, tenantParam, '', 'invalid_redirect');
  }

  const redirectValidation = await validateRedirectUrl(redirectUrl, env.TENANT_CONFIGS, env.ENVIRONMENT);
  if (!redirectValidation.valid) {
    if (silent) {
      return renderSilentRefreshResponse(
        { type: 'cp-auth-silent-refresh', error: 'no_session' },
        adminOrigin
      );
    }
    return redirectToLogin(env, tenantParam, '', 'invalid_redirect');
  }

  // ── Validate admin origin for silent mode ──
  // Silent refresh is only valid for admin SPA origins. If the redirect URL
  // points to a non-admin domain we fall through to top-level redirect to
  // prevent information leakage via postMessage to an arbitrary origin.
  if (silent) {
    try {
      const redirectHostname = new URL(redirectUrl).hostname;
      if (!isAdminDomain(redirectHostname)) {
        // Non-admin origin in silent mode — fall back to no-op (no redirect, no postMessage)
        return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
      }
      adminOrigin = new URL(redirectUrl).origin;
    } catch {
      return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
    }
  }

  // ── Extract refresh token from cookie ──
  const cookieHeader = request.headers.get('Cookie');
  const refreshTokenPlaintext = extractRefreshToken(cookieHeader);

  if (!refreshTokenPlaintext) {
    // No refresh token — redirect to login
    if (silent) {
      return renderSilentRefreshResponse(
        { type: 'cp-auth-silent-refresh', error: 'no_session' },
        adminOrigin
      );
    }
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired');
  }

  // ── Look up token in D1 ──
  const tokenHash = await hashRefreshToken(refreshTokenPlaintext);
  const existingToken = await db.getRefreshTokenByHash(tokenHash);

  if (!existingToken) {
    // Token not found — redirect to login with cleared cookie
    if (silent) {
      return renderSilentRefreshResponse(
        { type: 'cp-auth-silent-refresh', error: 'no_session' },
        adminOrigin
      );
    }
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired', true);
  }

  // ── Check if token was revoked (theft detection) ──
  if (existingToken.revoked_at !== null) {
    // REUSE DETECTED — revoke entire family
    console.error(
      `Refresh token reuse detected! Family=${existingToken.family_id}, User=${existingToken.user_id}`
    );
    await db.revokeRefreshTokenFamily(existingToken.family_id);
    if (silent) {
      return renderSilentRefreshResponse(
        { type: 'cp-auth-silent-refresh', error: 'session_revoked' },
        adminOrigin
      );
    }
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired', true);
  }

  // ── Check expiration ──
  const now = Math.floor(Date.now() / 1000);
  if (existingToken.expires_at <= now) {
    if (silent) {
      return renderSilentRefreshResponse(
        { type: 'cp-auth-silent-refresh', error: 'session_expired' },
        adminOrigin
      );
    }
    return redirectToLogin(env, tenantParam, redirectUrl, 'session_expired', true);
  }

  // ── Rotate token ──
  const newRefreshToken = generateRefreshToken();
  const newRefreshTokenHash = await hashRefreshToken(newRefreshToken);
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const newExpiresAt = Math.floor(Date.now() / 1000) + refreshTtlDays * 24 * 60 * 60;

  const newTokenId = generateUUID();
  const rotationResult = await db.rotateRefreshToken(tokenHash, {
    id: newTokenId,
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
    if (silent) {
      return renderSilentRefreshResponse(
        { type: 'cp-auth-silent-refresh', error: 'session_revoked' },
        adminOrigin
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
    // Pass the new token ID so token.ts can look up login_iat for the JWT claim
    refresh_token_id: newTokenId,
  });

  // ── Build new refresh cookie ──
  const refreshCookie = buildRefreshCookieHeader(newRefreshToken, refreshTtlDays, env.AUTH_DOMAIN);

  // ── Silent mode: return HTML with postMessage (no top-level redirect) ──
  if (silent) {
    const html = buildSilentSuccessHtml(authCode, adminOrigin);
    return new Response(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Set-Cookie': refreshCookie,
        'Cache-Control': 'no-store',
        'X-Frame-Options': 'ALLOWALL',
      },
    });
  }

  // ── Top-level redirect flow (no silent param) ──
  const returnUrl = new URL(redirectUrl);
  const callbackUrl = new URL('/auth/callback', returnUrl.origin);
  callbackUrl.searchParams.set('code', authCode);
  callbackUrl.searchParams.set('returnTo', returnUrl.pathname + returnUrl.search);

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
 * Build the success HTML for silent mode.
 * The auth code is placed in a data attribute (not inline JS) to avoid XSS.
 * Auth codes are 64-char hex strings; the admin origin has been validated.
 */
function buildSilentSuccessHtml(authCode: string, adminOrigin: string): string {
  const payload = JSON.stringify({ type: 'cp-auth-silent-refresh', code: authCode });
  const escapedPayload = escapeHtmlAttr(payload);
  const escapedOrigin = escapeHtmlAttr(adminOrigin);

  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<div id="cp-payload" data-payload='${escapedPayload}'></div>
<script>
(function(){
  var el=document.getElementById('cp-payload');
  try{parent.postMessage(JSON.parse(el.dataset.payload),'${escapedOrigin}');}catch(e){}
})();
</script>
</body>
</html>`;
}

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
