/**
 * Email Verification Completion Page (Phase 3.25 Tenant Access Gating)
 *
 * Rendered by handlers/verifyEmail.ts after a verification token is consumed.
 * Two states: success ("Email verified") and failure ("link invalid/expired").
 * Both render the tenant-branded auth shell (same chrome as login/register).
 *
 * The "Continue to sign in" link points at the auth-domain /login. We do NOT
 * accept or echo any redirect parameter on this page, so there is no untrusted
 * redirect to validate (redirect-validation discipline: nothing redirect-shaped
 * crosses this boundary).
 */
import type { Env } from '../types.js';
import type { TenantBranding } from '../branding.js';
import { renderAuthPage, escapeAttr } from './renderer.js';

export function renderVerifyEmailPage(
  env: Env,
  branding: TenantBranding,
  state: 'success' | 'failure',
  tenant: string | null,
): { html: string; status: number } {
  // Return the verified user to the TENANT's own login (the inline storefront login),
  // not the bare auth domain. `branding.domain` is the tenant's authoritative hostname
  // (resolved from its config, never a raw request param) — safe to link to. Falls back
  // to the auth-domain /login only when the tenant/domain can't be resolved.
  const loginHref = branding.domain
    ? `https://${branding.domain}/login`
    : `${env.AUTH_DOMAIN}/login?tenant=${encodeURIComponent(tenant || '')}`;

  const body = state === 'success'
    ? `
      <h1 class="auth-card__title">Email Verified</h1>
      <p class="auth-card__subtitle">Your email address has been confirmed. You can now sign in.</p>
      <a class="btn-primary" href="${escapeAttr(loginHref)}">Continue to Sign In</a>
    `
    : `
      <h1 class="auth-card__title">Verification Failed</h1>
      <p class="auth-card__subtitle">This verification link is invalid or has expired. Please register again or request a new link.</p>
      <a class="btn-primary" href="${escapeAttr(loginHref)}">Go to Sign In</a>
    `;

  const html = renderAuthPage(
    branding,
    { title: state === 'success' ? 'Email Verified' : 'Verification Failed', body },
    env.PLATFORM_DOMAIN,
  );

  return { html, status: state === 'success' ? 200 : 400 };
}
