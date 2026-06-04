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
import { parseRequestBody } from '../util/parseRequestBody.js';
import { ConsoleJsonLogger } from '../core/logger.js';
import { logAuthEvent } from '../security/auditLog.js';

const logger = new ConsoleJsonLogger();

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
    const body = await parseRequestBody(request);

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
    // ── Narrow-deny guard (Fix — Customer Storefront Auth, S2) ──
    // The /forgot-password page is PUBLIC and reachable by anyone: privileged
    // users (legit self-reset), brand-new sellers mid-onboarding (user row
    // exists, membership not yet provisioned), orphaned/no-membership users, and
    // legacy pure-customers. We DENY a reset here ONLY for a CONFIRMED
    // PURE-CUSTOMER — an account that holds an active `customer` membership on
    // some tenant AND holds NO privileged context. Such a user should reset via
    // their storefront (the runtime /reset-password page), not the auth domain.
    // Everyone else — privileged, no-membership/onboarding, and mixed-context
    // users — still gets the reset. A broad "only privileged may reset" rule
    // would lock out onboarding sellers and orphaned users; this is the exact
    // bug this guard must NOT introduce, hence the narrow deny.
    const isCustomerSomewhere = await db.hasAnyCustomerMembership(user.id);
    const isPrivileged = await db.hasPrivilegedMembership(user.id);

    if (isCustomerSomewhere && !isPrivileged) {
      // Confirmed pure-customer: refuse on the auth domain. Keep a constant-time
      // dummy-work path so the deny branch does not run conspicuously faster than
      // the allow branch (which does token gen + hash + DB insert + email send),
      // and audit the refusal WITHOUT leaking anything to the caller.
      await dummyHashDelay();
      logAuthEvent(logger, {
        event: 'auth_reset_refused_pure_customer',
        ip: auditIp(request),
        route: '/api/forgot-password',
        userAgent: request.headers.get('User-Agent'),
        userId: user.id,
        statusCode: 302,
        correlationId: correlationOf(request),
      });
      return successRedirect(env, tenantParam, redirectUrl);
    }

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
    // Outside a tenant storefront context (platform-admin password reset),
    // tenantParam is empty. Fall back to PLATFORM_TENANT_ID so the
    // transactional renderer can resolve a real tenant row and brand the
    // email under the platform's own identity.
    const effectiveTenantId = tenantParam || env.PLATFORM_TENANT_ID;
    // Preserve the original redirect target through the email round-trip so
    // we can return the user to the right app (admin SPA or storefront) after
    // they set a new password. PKCE state cannot survive the round-trip, so
    // we land them at the redirect's origin, where the app re-initiates a
    // fresh login flow with its own PKCE.
    const redirectQuery = redirectUrl ? `&redirect=${encodeURIComponent(redirectUrl)}` : '';
    const resetUrl = `${env.AUTH_DOMAIN}/reset-password?token=${resetToken}&tenant=${encodeURIComponent(tenantParam)}${redirectQuery}`;
    const branding = await loadTenantBranding(effectiveTenantId || null, env);
    await sendPasswordResetEmail(env, user.email, resetUrl, branding, {
      tenantId: effectiveTenantId,
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

/**
 * Dummy PBKDF2 work to keep timing consistent across the deny branch (mirrors
 * handlers/login.ts / internalCustomerAuth.ts). The allow branch does token gen
 * + hash + DB insert + branded email send; the pure-customer deny branch must
 * not betray itself by returning conspicuously faster.
 */
async function dummyHashDelay(): Promise<void> {
  const dummyKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('dummy-password'),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new Uint8Array(32), iterations: 100_000, hash: 'SHA-256' },
    dummyKey,
    256,
  );
}

function auditIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')
    || 'internal';
}

function correlationOf(request: Request): string {
  return request.headers.get('x-correlation-id')
    || request.headers.get('x-request-id')
    || 'unknown';
}
