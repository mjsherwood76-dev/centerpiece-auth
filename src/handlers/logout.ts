/**
 * Logout Handler
 *
 * POST /api/logout — Revoke current refresh token (single session)
 * POST /api/logout-all — Revoke ALL refresh tokens for the user (all sessions)
 * GET  /api/logout?redirect_uri=… — Revoke + redirect (top-level navigation)
 *
 * All endpoints:
 * - Read refresh token from HttpOnly cookie
 * - Revoke in D1
 * - Clear the refresh cookie via Set-Cookie
 *
 * POST returns 200 JSON; GET 302s back to a validated redirect_uri.
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import {
  extractRefreshToken,
  hashRefreshToken,
  buildClearRefreshCookieHeader,
} from '../crypto/refreshTokens.js';
import { validateRedirectUrl } from '../security/redirectValidator.js';

/**
 * Handle POST /api/logout — revoke the current refresh token.
 */
export async function handleLogout(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const cookieHeader = request.headers.get('Cookie');
  const refreshTokenPlaintext = extractRefreshToken(cookieHeader);

  if (refreshTokenPlaintext) {
    const tokenHash = await hashRefreshToken(refreshTokenPlaintext);
    await db.revokeRefreshToken(tokenHash);
  }

  const clearCookie = buildClearRefreshCookieHeader(env.AUTH_DOMAIN);

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': clearCookie,
      'Cache-Control': 'no-store',
    },
  });
}

/**
 * Handle GET /api/logout?redirect_uri=… — revoke the current refresh token and
 * redirect the browser back to the caller.
 *
 * The admin SPA logs out via a top-level navigation (not fetch) so the
 * first-party refresh cookie is sent even when third-party cookies are blocked.
 * It expects a 302 back to its origin, where the now-token-less SPA re-runs its
 * login flow.
 *
 * `redirect_uri` is validated to prevent an open redirect — any missing or
 * invalid target falls back to the auth login page.
 */
export async function handleLogoutRedirect(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const cookieHeader = request.headers.get('Cookie');
  const refreshTokenPlaintext = extractRefreshToken(cookieHeader);

  if (refreshTokenPlaintext) {
    const tokenHash = await hashRefreshToken(refreshTokenPlaintext);
    await db.revokeRefreshToken(tokenHash);
  }

  const clearCookie = buildClearRefreshCookieHeader(env.AUTH_DOMAIN);

  const redirectUri = new URL(request.url).searchParams.get('redirect_uri') || '';
  let location = `${env.AUTH_DOMAIN}/login`;
  if (redirectUri) {
    const validation = await validateRedirectUrl(redirectUri, env.TENANT_CONFIGS, env.ENVIRONMENT);
    if (validation.valid) {
      location = redirectUri;
    }
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: location,
      'Set-Cookie': clearCookie,
      'Cache-Control': 'no-store',
    },
  });
}

/**
 * Handle POST /api/logout-all — revoke ALL refresh tokens for the user.
 */
export async function handleLogoutAll(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const cookieHeader = request.headers.get('Cookie');
  const refreshTokenPlaintext = extractRefreshToken(cookieHeader);

  if (refreshTokenPlaintext) {
    const tokenHash = await hashRefreshToken(refreshTokenPlaintext);
    const existingToken = await db.getRefreshTokenByHash(tokenHash);

    if (existingToken) {
      // Revoke ALL tokens for this user
      await db.revokeAllRefreshTokensForUser(existingToken.user_id);
    }
  }

  const clearCookie = buildClearRefreshCookieHeader(env.AUTH_DOMAIN);

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': clearCookie,
      'Cache-Control': 'no-store',
    },
  });
}
