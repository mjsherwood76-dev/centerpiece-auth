/**
 * Logout Handler
 *
 * POST /api/logout — Revoke current refresh token (single session)
 * POST /api/logout-all — Revoke ALL refresh tokens for the user (all sessions)
 *
 * Both endpoints:
 * - Read refresh token from HttpOnly cookie
 * - Revoke in D1
 * - Clear the refresh cookie via Set-Cookie
 * - Return 200 with cleared cookie
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import {
  extractRefreshToken,
  hashRefreshToken,
  buildClearRefreshCookieHeader,
} from '../crypto/refreshTokens.js';

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
