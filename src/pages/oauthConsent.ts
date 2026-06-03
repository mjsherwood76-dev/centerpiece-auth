/**
 * OAuth Third-Party Consent Screen
 *
 * Rendered by GET /oauth/authorize once the request has passed every RFC 6749 +
 * security validation (active client, exact redirect_uri allow-list match,
 * scope ⊆ client allowed scopes, logged-in seller). Shows the requesting
 * client's name and the human-readable list of requested permissions, with
 * Allow / Deny buttons that POST back to /oauth/authorize/decision.
 *
 * Copy is deliberately non-technical (memory:
 * project_seller_persona_ai_creates_seller_modifies). Sellers are small
 * businesses, not security engineers — they see "View your orders", never
 * "orders:read".
 *
 * The form carries two hidden fields:
 * - `request`: the HMAC-signed consent request (tamper-proof original params +
 *   user_id + csrf + expiry). The decision handler trusts THIS, not re-submitted
 *   params.
 * - `csrf`: the same CSRF nonce embedded in the signed request (double-submit).
 *
 * @module pages/oauthConsent
 */
import type { TenantBranding } from '../branding.js';
import { renderAuthPage, escapeHtml, escapeAttr } from './renderer.js';

/**
 * Human-readable text for each supported scope. Keyed by the scope string the
 * client requests; the value is what the seller actually reads. Any scope not
 * in this map falls back to a generic line (it will already have passed the
 * supported-scope allow-list, so this is defence-in-depth, not validation).
 */
export const SCOPE_HUMAN_TEXT: Record<string, string> = {
  openid: 'Confirm your identity',
  profile: 'View your basic profile information',
  email: 'View your email address',
  'tenant:read': 'View your store configuration',
  'tenant:write': 'Update your store configuration',
  'orders:read': 'View your orders',
  'orders:write': 'Manage your orders',
};

/** Map a scope string to its human-readable consent line. */
export function humanScopeText(scope: string): string {
  return SCOPE_HUMAN_TEXT[scope] ?? `Access: ${scope}`;
}

export interface ConsentScreenParams {
  branding: TenantBranding;
  platformDomain: string;
  /** Display name of the requesting third-party client. */
  clientName: string;
  /** Requested scopes (already validated). */
  scopes: string[];
  /** Action URL for the Allow/Deny form (the decision endpoint). */
  decisionUrl: string;
  /** HMAC-signed consent request token. */
  signedRequest: string;
  /** CSRF nonce (also embedded inside signedRequest). */
  csrfToken: string;
}

/**
 * Render the consent screen HTML document.
 */
export function renderConsentScreen(params: ConsentScreenParams): string {
  const scopeItems = params.scopes
    .map(
      (s) => `
        <li class="consent-scope">
          <svg class="consent-scope__icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
          <span>${escapeHtml(humanScopeText(s))}</span>
        </li>`,
    )
    .join('');

  const body = `
    <h1 class="auth-card__title">Authorize access</h1>
    <p class="auth-card__subtitle">
      <strong>${escapeHtml(params.clientName)}</strong> is requesting permission to access your account.
    </p>

    <p class="consent-intro">This app will be able to:</p>
    <ul class="consent-scopes">
      ${scopeItems}
    </ul>

    <p class="consent-note">
      Only allow access if you trust <strong>${escapeHtml(params.clientName)}</strong>.
      You can revoke this access at any time.
    </p>

    <form class="auth-form consent-form" method="POST" action="${escapeAttr(params.decisionUrl)}">
      <input type="hidden" name="request" value="${escapeAttr(params.signedRequest)}">
      <input type="hidden" name="csrf" value="${escapeAttr(params.csrfToken)}">
      <div class="consent-actions">
        <button class="btn-secondary" type="submit" name="decision" value="deny">Deny</button>
        <button class="btn-primary" type="submit" name="decision" value="allow">Allow</button>
      </div>
    </form>

    <style>
      .consent-intro { font-size: 0.875rem; color: hsl(var(--foreground)); margin-bottom: 0.5rem; }
      .consent-scopes { list-style: none; display: flex; flex-direction: column; gap: 0.5rem; margin: 0 0 1.25rem; padding: 0; }
      .consent-scope { display: flex; align-items: flex-start; gap: 0.625rem; font-size: 0.9375rem; color: hsl(var(--foreground)); }
      .consent-scope__icon { flex-shrink: 0; margin-top: 0.1875rem; color: hsl(var(--primary)); }
      .consent-note { font-size: 0.8125rem; color: hsl(var(--muted-foreground)); margin-bottom: 1.25rem; }
      .consent-actions { display: flex; gap: 0.75rem; }
      .consent-actions .btn-primary, .consent-actions .btn-secondary { flex: 1; }
      .btn-secondary {
        display: inline-flex; align-items: center; justify-content: center;
        height: var(--control-height, 40px); padding: 0 1.5rem; border: 1px solid hsl(var(--border));
        border-radius: var(--button-radius, 8px); background: hsl(var(--background));
        color: hsl(var(--foreground)); font-size: 0.875rem; font-weight: 500; font-family: inherit; cursor: pointer;
        transition: background var(--motion-fast, 150ms) var(--motion-ease, ease);
      }
      .btn-secondary:hover { background: hsl(var(--muted)); }
      .btn-secondary:focus-visible { outline: 2px solid hsl(var(--ring)); outline-offset: 2px; }
    </style>
  `;

  return renderAuthPage(params.branding, { title: 'Authorize access', body }, params.platformDomain);
}
