/**
 * Forgot Password Handler
 *
 * POST /api/forgot-password — Request a password reset
 *
 * Flow:
 * 1. Parse email and tenantId from form body
 * 2. Look up user by email
 * 3. Generate cryptographically random reset token
 * 4. Store SHA-256 hash in `password_reset_tokens` with 1-hour TTL
 * 5. STUB: Log the reset link (real email delivery wired in Phase 1B.3)
 * 6. Always return generic success message (account enumeration prevention)
 *
 * Security:
 * - Never reveal whether the email exists
 * - Reset token stored as hash (never plaintext)
 * - 1-hour TTL on reset tokens
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { sha256Hex } from '../crypto/jwt.js';
import { generateAuthCode } from '../crypto/refreshTokens.js';
import { loadTenantBranding } from '../branding.js';
import { sendPasswordResetEmail } from '../email/send.js';

/**
 * Handle POST /api/forgot-password
 *
 * Accepts form-urlencoded or JSON body: { email, tenant }
 */
export async function handleForgotPassword(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Parse body ──
  let email: string;
  let tenantParam: string;
  let redirectUrl: string;

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

    email = (body.email || '').trim().toLowerCase();
    tenantParam = (body.tenant || '').trim();
    redirectUrl = (body.redirect || '').trim();
  } catch {
    return successRedirect(env, tenantParam!, redirectUrl!);
  }

  // ── Always return the same generic response ──
  // Account enumeration prevention: "If that email exists, we sent a reset link"
  if (!email) {
    return successRedirect(env, tenantParam, redirectUrl);
  }

  // ── Look up user (but never reveal if they exist) ──
  const user = await db.getUserByEmail(email);

  if (user) {
    // Generate reset token
    const resetToken = generateAuthCode(); // 256-bit random hex
    const resetTokenHash = await sha256Hex(resetToken);
    const expiresAt = Math.floor(Date.now() / 1000) + 3600; // 1-hour TTL

    await db.insertPasswordResetToken({
      token_hash: resetTokenHash,
      user_id: user.id,
      expires_at: expiresAt,
    });

    // ── Send password reset email ──
    const resetUrl = `${env.AUTH_DOMAIN}/reset-password?token=${resetToken}&tenant=${encodeURIComponent(tenantParam)}`;
    const branding = await loadTenantBranding(tenantParam || null, env);
    await sendPasswordResetEmail(env, user.email, resetUrl, branding, {
      tenantId: tenantParam || undefined,
      userId: user.id,
    });
  }

  // ── Always redirect with success message (never reveal email existence) ──
  return successRedirect(env, tenantParam, redirectUrl);
}

/**
 * Redirect back to login page with a generic success message.
 */
function successRedirect(env: Env, tenant: string, redirect: string): Response {
  const params = new URLSearchParams();
  if (tenant) params.set('tenant', tenant);
  if (redirect) params.set('redirect', redirect);
  params.set('message', 'reset_sent');

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.AUTH_DOMAIN}/login?${params.toString()}`,
      'Cache-Control': 'no-store',
    },
  });
}
