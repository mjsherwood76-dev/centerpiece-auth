/**
 * Login Page Handler
 *
 * Route: GET /login?tenant={tenantId}&redirect={returnUrl}
 *
 * Renders a branded login page with:
 * - Email + password form
 * - OAuth buttons (Google, Facebook, Apple, Microsoft)
 * - "Forgot password?" link
 * - "Don't have an account? Sign up" link
 *
 * English-only in this phase. Multi-locale auth pages deferred
 * until auth UI is stable.
 */
import type { Env } from '../types.js';
import { loadTenantBranding } from '../branding.js';
import { renderAuthPage, oauthIcons, escapeHtml, escapeAttr } from './renderer.js';

/**
 * Handle GET /login — render the branded login page.
 */
export async function handleLoginPage(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const tenant = url.searchParams.get('tenant');
  const redirect = url.searchParams.get('redirect') || '';
  const error = url.searchParams.get('error');
  const message = url.searchParams.get('message');

  const branding = await loadTenantBranding(tenant, env);

  // Build OAuth URLs
  const oauthBase = `${env.AUTH_DOMAIN}/oauth`;
  const oauthParams = buildOAuthParams(tenant, redirect);

  const body = `
    <h1 class="auth-card__title">Sign In</h1>
    <p class="auth-card__subtitle">Welcome back. Sign in to your account.</p>

    ${message ? `<div class="auth-success" data-visible="true">${escapeHtml(getSuccessMessage(message))}</div>` : ''}
    ${error ? `<div class="auth-error" data-visible="true">${escapeHtml(getErrorMessage(error))}</div>` : '<div class="auth-error" id="auth-error"></div>'}

    <form class="auth-form" method="POST" action="${escapeAttr(env.AUTH_DOMAIN)}/api/login" id="login-form">
      <input type="hidden" name="tenant" value="${escapeAttr(tenant || '')}">
      <input type="hidden" name="redirect" value="${escapeAttr(redirect)}">

      <div class="form-group">
        <label class="form-label" for="email">Email</label>
        <input class="form-input" type="email" id="email" name="email" placeholder="you@example.com" required autocomplete="email" autofocus>
      </div>

      <div class="form-group">
        <label class="form-label" for="password">Password</label>
        <input class="form-input" type="password" id="password" name="password" placeholder="Enter your password" required autocomplete="current-password" minlength="8">
      </div>

      <div class="auth-forgot">
        <a class="auth-link" href="${escapeAttr(env.AUTH_DOMAIN)}/reset-password?tenant=${encodeURIComponent(tenant || '')}&redirect=${encodeURIComponent(redirect)}">Forgot password?</a>
      </div>

      <button class="btn-primary" type="submit">Sign In</button>
    </form>

    <div class="auth-divider">
      <span class="auth-divider__text">or</span>
    </div>

    <div class="oauth-buttons">
      <a class="btn-oauth" href="${escapeAttr(oauthBase)}/google?${oauthParams}">
        ${oauthIcons.google}
        Continue with Google
      </a>
      <a class="btn-oauth" href="${escapeAttr(oauthBase)}/facebook?${oauthParams}">
        ${oauthIcons.facebook}
        Continue with Facebook
      </a>
      <a class="btn-oauth" href="${escapeAttr(oauthBase)}/apple?${oauthParams}">
        ${oauthIcons.apple}
        Continue with Apple
      </a>
      <a class="btn-oauth" href="${escapeAttr(oauthBase)}/microsoft?${oauthParams}">
        ${oauthIcons.microsoft}
        Continue with Microsoft
      </a>
    </div>

    <p class="auth-footer-link">
      Don't have an account?
      <a class="auth-link" href="${escapeAttr(env.AUTH_DOMAIN)}/register?tenant=${encodeURIComponent(tenant || '')}&redirect=${encodeURIComponent(redirect)}">Sign up</a>
    </p>
  `;

  const html = renderAuthPage(branding, { title: 'Sign In', body });

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

// ─── Helpers ────────────────────────────────────────────────

function buildOAuthParams(tenant: string | null, redirect: string): string {
  const params = new URLSearchParams();
  if (tenant) params.set('tenant', tenant);
  if (redirect) params.set('redirect', redirect);
  return params.toString();
}

/**
 * Map success message codes to user-facing messages.
 */
function getSuccessMessage(code: string): string {
  switch (code) {
    case 'reset_sent':
      return 'If that email is registered, we sent a password reset link. Check your inbox.';
    case 'password_changed':
      return 'Your password has been changed successfully. Please sign in.';
    default:
      return '';
  }
}

/**
 * Map error codes to user-facing messages.
 * Account enumeration prevention: never reveal whether an email exists.
 */
function getErrorMessage(code: string): string {
  switch (code) {
    case 'invalid_credentials':
      return 'Invalid email or password.';
    case 'account_locked':
      return 'This account has been temporarily locked. Please try again later.';
    case 'session_expired':
      return 'Your session has expired. Please sign in again.';
    case 'oauth_failed':
      return 'Authentication with the provider failed. Please try again.';
    case 'invalid_redirect':
      return 'The return URL is not valid. Please try again from the store.';
    default:
      return 'An error occurred. Please try again.';
  }
}
