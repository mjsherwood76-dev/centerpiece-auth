/**
 * Reset Password Handler
 *
 * POST /api/reset-password — Complete a password reset
 *
 * Flow:
 * 1. Parse token and new password from form body
 * 2. Hash the token, look up in `password_reset_tokens`
 * 3. Verify: not expired, not already used
 * 4. Mark token as used
 * 5. Hash new password, update user's `password_hash`
 * 6. Revoke ALL refresh tokens for the user (invalidate all sessions)
 * 7. Redirect to login with success message
 *
 * Security:
 * - Token stored as SHA-256 hash (never plaintext)
 * - Single-use (marked as used on consumption)
 * - All sessions invalidated after password change
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { sha256Hex } from '../crypto/jwt.js';
import { hashPassword } from '../crypto/passwords.js';

/**
 * Handle POST /api/reset-password
 *
 * Accepts form-urlencoded or JSON body: { token, newPassword, confirmPassword, tenant }
 */
export async function handleResetPassword(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Parse body ──
  let token: string;
  let newPassword: string;
  let confirmPassword: string;
  let tenantParam: string;

  try {
    const contentType = request.headers.get('Content-Type') || '';
    let body: Record<string, string>;

    if (contentType.includes('application/json')) {
      body = (await request.json()) as Record<string, string>;
    } else {
      const formData = await request.formData();
      body = {} as Record<string, string>;
      formData.forEach((value, key) => {
        if (typeof value === 'string') body[key] = value;
      });
    }

    token = (body.token || '').trim();
    newPassword = body.newPassword || body.password || '';
    confirmPassword = body.confirmPassword || body.password || '';
    tenantParam = (body.tenant || '').trim();
  } catch {
    return errorRedirect(env, '', 'invalid_token');
  }

  // ── Validate inputs ──
  if (!token) {
    return errorRedirect(env, tenantParam, 'invalid_token');
  }

  if (newPassword.length < 8) {
    return errorRedirect(env, tenantParam, 'password_weak', token);
  }

  if (newPassword !== confirmPassword) {
    return errorRedirect(env, tenantParam, 'password_mismatch', token);
  }

  // ── Look up token ──
  const tokenHash = await sha256Hex(token);
  const resetRow = await db.consumePasswordResetToken(tokenHash);

  if (!resetRow) {
    return errorRedirect(env, tenantParam, 'invalid_token');
  }

  // ── Check expiration ──
  const now = Math.floor(Date.now() / 1000);
  if (resetRow.expires_at <= now) {
    return errorRedirect(env, tenantParam, 'token_expired');
  }

  // ── Hash new password and update user ──
  const passwordHash = await hashPassword(newPassword);
  await db.updateUserPassword(resetRow.user_id, passwordHash);

  // ── Revoke ALL refresh tokens for the user ──
  // This invalidates all existing sessions (security: password changed)
  await db.revokeAllRefreshTokensForUser(resetRow.user_id);

  console.log(`[PASSWORD_RESET] Password changed for user ${resetRow.user_id}. All sessions invalidated.`);

  // ── Redirect to login with success message ──
  const params = new URLSearchParams();
  if (tenantParam) params.set('tenant', tenantParam);
  params.set('message', 'password_changed');

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.AUTH_DOMAIN}/login?${params.toString()}`,
      'Cache-Control': 'no-store',
    },
  });
}

/**
 * Redirect back to the reset password page with an error code.
 */
function errorRedirect(env: Env, tenant: string, error: string, token?: string): Response {
  const params = new URLSearchParams();
  if (tenant) params.set('tenant', tenant);
  if (token) params.set('token', token);
  params.set('error', error);

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.AUTH_DOMAIN}/reset-password?${params.toString()}`,
      'Cache-Control': 'no-store',
    },
  });
}
