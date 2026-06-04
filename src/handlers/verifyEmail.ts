/**
 * Email Verification Handler (Phase 3.25 Tenant Access Gating)
 *
 *   GET /verify-email?token=…&tenant=…
 *
 * Consumes a one-time email-verification token (minted at gated-tenant
 * registration — handlers/emailVerification.ts), and on success sets
 * `users.email_verified = 1`. Renders a tenant-branded completion page.
 *
 * Security:
 * - The token is looked up by SHA-256 hash; plaintext is never stored.
 * - One-shot: `consumeEmailVerificationToken` marks `consumed_at` on first use,
 *   so a reused link returns null → failure page. Expired tokens fail closed.
 * - `tenant` is a branding hint only (drives the completion page chrome + the
 *   sign-in link); it is NOT a trust boundary and produces no redirect.
 * - No redirect is constructed from any request parameter — the only outbound
 *   link is the hardcoded auth-domain /login (redirect-validation discipline).
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { sha256Hex } from '../crypto/jwt.js';
import { loadTenantBranding } from '../branding.js';
import { renderVerifyEmailPage } from '../pages/verifyEmail.js';

function pageResponse(html: string, status: number): Response {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

export async function handleVerifyEmail(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = (url.searchParams.get('token') || '').trim();
  const tenant = url.searchParams.get('tenant');

  const branding = await loadTenantBranding(tenant, env);

  if (!token) {
    const { html, status } = renderVerifyEmailPage(env, branding, 'failure', tenant);
    return pageResponse(html, status);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const tokenHash = await sha256Hex(token);
  const row = await db.consumeEmailVerificationToken(tokenHash);

  // Fail closed on missing/reused token or expiry — never reveal which.
  const now = Math.floor(Date.now() / 1000);
  if (!row || row.expires_at <= now) {
    const { html, status } = renderVerifyEmailPage(env, branding, 'failure', tenant);
    return pageResponse(html, status);
  }

  await db.markEmailVerified(row.user_id);

  const { html, status } = renderVerifyEmailPage(env, branding, 'success', tenant);
  return pageResponse(html, status);
}
