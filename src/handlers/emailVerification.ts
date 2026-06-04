/**
 * Email-verification token issuance (Phase 3.25 Tenant Access Gating).
 *
 * Shared by both register paths (auth-domain `handlers/register.ts` and inline
 * `handlers/internalCustomerAuth.ts`). When the target tenant is GATED, mint a
 * one-time verification token (store only its SHA-256 hash + TTL) and send a
 * tenant-branded verification email. The link targets the auth-domain
 * `/verify-email` handler, which consumes the token and sets
 * `users.email_verified = 1` (handlers/verifyEmail.ts).
 *
 * Non-blocking and fail-soft: registration succeeds regardless of email
 * delivery. On an ungated tenant this is a no-op.
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { sha256Hex } from '../crypto/jwt.js';
import { generateAuthCode, generateUUID } from '../crypto/refreshTokens.js';
import { loadTenantBranding } from '../branding.js';
import { loadTenantGating } from '../security/tenantGating.js';
import { sendEmailVerificationEmail } from '../email/send.js';

/** One-hour TTL, matching the password-reset token lifetime. */
const VERIFICATION_TTL_SECONDS = 3600;

/**
 * If `tenantId` is gated, issue a verification token for `user` and send the
 * verification email. Safe to call unconditionally — returns immediately for
 * ungated tenants.
 */
export async function maybeSendVerificationForGatedTenant(
  env: Env,
  db: AuthDB,
  tenantId: string,
  user: { id: string; email: string },
): Promise<void> {
  const gating = await loadTenantGating(env, tenantId || null);
  if (!gating.gated) return;

  const token = generateAuthCode();
  const tokenHash = await sha256Hex(token);
  const now = Math.floor(Date.now() / 1000);

  await db.insertEmailVerificationToken({
    id: generateUUID(),
    user_id: user.id,
    token_hash: tokenHash,
    expires_at: now + VERIFICATION_TTL_SECONDS,
    created_at: now,
  });

  const verificationUrl = `${env.AUTH_DOMAIN}/verify-email?token=${token}`;
  const branding = await loadTenantBranding(tenantId, env);
  await sendEmailVerificationEmail(env, user.email, verificationUrl, branding, {
    tenantId,
    userId: user.id,
  });
}
