/**
 * Register Page Handler
 *
 * Route: GET /register?tenant={tenantId}&redirect={returnUrl}
 *
 * Renders a branded registration page with:
 * - Name, email, password, confirm password fields
 * - OAuth buttons (Google, Facebook, Apple, Microsoft)
 * - "Already have an account? Sign in" link
 *
 * English-only in this phase. Multi-locale auth pages deferred
 * until auth UI is stable.
 */
import type { Env } from '../types.js';
import { loadTenantBranding } from '../branding.js';
import { renderAuthPage, oauthIcons, escapeHtml, escapeAttr } from './renderer.js';

/**
 * Handle GET /register — render the branded register page.
 */
export async function handleRegisterPage(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const tenant = url.searchParams.get('tenant');
  const redirect = url.searchParams.get('redirect') || '';
  const error = url.searchParams.get('error');

  const branding = await loadTenantBranding(tenant, env);

  // Build OAuth URLs
  const oauthBase = `${env.AUTH_DOMAIN}/oauth`;
  const oauthParams = buildOAuthParams(tenant, redirect);

  const body = `
    <h1 class="auth-card__title">Create Account</h1>
    <p class="auth-card__subtitle">Create your account to get started.</p>

    ${error ? `<div class="auth-error" data-visible="true">${escapeHtml(getErrorMessage(error))}</div>` : '<div class="auth-error" id="auth-error"></div>'}

    <form class="auth-form" method="POST" action="${escapeAttr(env.AUTH_DOMAIN)}/api/register" id="register-form">
      <input type="hidden" name="tenant" value="${escapeAttr(tenant || '')}">
      <input type="hidden" name="redirect" value="${escapeAttr(redirect)}">

      <div class="form-group">
        <label class="form-label" for="name">Name</label>
        <input class="form-input" type="text" id="name" name="name" placeholder="Your name" required autocomplete="name" autofocus>
      </div>

      <div class="form-group">
        <label class="form-label" for="email">Email</label>
        <input class="form-input" type="email" id="email" name="email" placeholder="you@example.com" required autocomplete="email">
      </div>

      <div class="form-group">
        <label class="form-label" for="password">Password</label>
        <input class="form-input" type="password" id="password" name="password" placeholder="Create a password" required autocomplete="new-password" minlength="8">
      </div>

      <div class="form-group">
        <label class="form-label" for="confirm-password">Confirm Password</label>
        <input class="form-input" type="password" id="confirm-password" name="confirmPassword" placeholder="Confirm your password" required autocomplete="new-password" minlength="8">
      </div>

      <button class="btn-primary" type="submit">Create Account</button>
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
      Already have an account?
      <a class="auth-link" href="${escapeAttr(env.AUTH_DOMAIN)}/login?tenant=${encodeURIComponent(tenant || '')}&redirect=${encodeURIComponent(redirect)}">Sign in</a>
    </p>
  `;

  // Client-side password match validation
  const clientScript = `
  <script>
    (function() {
      var form = document.getElementById('register-form');
      if (!form) return;
      form.addEventListener('submit', function(e) {
        var pw = document.getElementById('password');
        var cpw = document.getElementById('confirm-password');
        var errEl = document.getElementById('auth-error');
        if (pw.value !== cpw.value) {
          e.preventDefault();
          if (errEl) {
            errEl.textContent = 'Passwords do not match.';
            errEl.setAttribute('data-visible', 'true');
          }
          cpw.focus();
          return false;
        }
        if (pw.value.length < 8) {
          e.preventDefault();
          if (errEl) {
            errEl.textContent = 'Password must be at least 8 characters.';
            errEl.setAttribute('data-visible', 'true');
          }
          pw.focus();
          return false;
        }
      });
    })();
  </script>`;

  const html = renderAuthPage(branding, { title: 'Create Account', body: body + clientScript });

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
 * Map error codes to user-facing messages.
 */
function getErrorMessage(code: string): string {
  switch (code) {
    case 'email_exists':
      return 'An account with this email already exists. Please sign in instead.';
    case 'password_mismatch':
      return 'Passwords do not match.';
    case 'password_weak':
      return 'Password must be at least 8 characters.';
    case 'invalid_email':
      return 'Please enter a valid email address.';
    case 'invalid_redirect':
      return 'The return URL is not valid. Please try again from the store.';
    case 'oauth_failed':
      return 'Authentication with the provider failed. Please try again.';
    default:
      return 'An error occurred. Please try again.';
  }
}
