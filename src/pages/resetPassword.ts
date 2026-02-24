/**
 * Reset Password Page Handler
 *
 * Route: GET /reset-password?token={resetToken}&tenant={tenantId}
 *
 * Two modes:
 * 1. No token: shows "forgot password" form (email input)
 * 2. With token: shows "new password" form (password + confirm)
 *
 * Branded to match the tenant's theme (same as login/register pages).
 * English-only in this phase.
 */
import type { Env } from '../types.js';
import { loadTenantBranding } from '../branding.js';
import { renderAuthPage, escapeHtml, escapeAttr } from './renderer.js';

/**
 * Handle GET /reset-password — render the branded reset password page.
 */
export async function handleResetPasswordPage(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const tenant = url.searchParams.get('tenant');
  const redirect = url.searchParams.get('redirect') || '';
  const token = url.searchParams.get('token');
  const error = url.searchParams.get('error');

  const branding = await loadTenantBranding(tenant, env);

  const body = token
    ? renderNewPasswordForm(env, tenant, token, error)
    : renderForgotPasswordForm(env, tenant, redirect, error);

  const pageTitle = token ? 'Reset Password' : 'Forgot Password';

  const html = renderAuthPage(branding, { title: pageTitle, body });

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

/**
 * Render the "forgot password" form (email input → POST /api/forgot-password).
 */
function renderForgotPasswordForm(
  env: Env,
  tenant: string | null,
  redirect: string,
  error: string | null
): string {
  return `
    <h1 class="auth-card__title">Forgot Password</h1>
    <p class="auth-card__subtitle">Enter your email and we'll send you a link to reset your password.</p>

    ${error ? `<div class="auth-error" data-visible="true">${escapeHtml(getErrorMessage(error))}</div>` : '<div class="auth-error" id="auth-error"></div>'}

    <form class="auth-form" method="POST" action="${escapeAttr(env.AUTH_DOMAIN)}/api/forgot-password" id="forgot-form">
      <input type="hidden" name="tenant" value="${escapeAttr(tenant || '')}">
      <input type="hidden" name="redirect" value="${escapeAttr(redirect)}">

      <div class="form-group">
        <label class="form-label" for="email">Email</label>
        <input class="form-input" type="email" id="email" name="email" placeholder="you@example.com" required autocomplete="email" autofocus>
      </div>

      <button class="btn-primary" type="submit">Send Reset Link</button>
    </form>

    <p class="auth-footer-link">
      Remember your password?
      <a class="auth-link" href="${escapeAttr(env.AUTH_DOMAIN)}/login?tenant=${encodeURIComponent(tenant || '')}&redirect=${encodeURIComponent(redirect)}">Sign in</a>
    </p>
  `;
}

/**
 * Render the "new password" form (password + confirm → POST /api/reset-password).
 */
function renderNewPasswordForm(
  env: Env,
  tenant: string | null,
  token: string,
  error: string | null
): string {
  const clientScript = `
  <script>
    (function() {
      var form = document.getElementById('reset-form');
      if (!form) return;
      form.addEventListener('submit', function(e) {
        var pw = document.getElementById('newPassword');
        var cpw = document.getElementById('confirmPassword');
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

  return `
    <h1 class="auth-card__title">Reset Password</h1>
    <p class="auth-card__subtitle">Enter your new password below.</p>

    ${error ? `<div class="auth-error" data-visible="true">${escapeHtml(getErrorMessage(error))}</div>` : '<div class="auth-error" id="auth-error"></div>'}

    <form class="auth-form" method="POST" action="${escapeAttr(env.AUTH_DOMAIN)}/api/reset-password" id="reset-form">
      <input type="hidden" name="token" value="${escapeAttr(token)}">
      <input type="hidden" name="tenant" value="${escapeAttr(tenant || '')}">

      <div class="form-group">
        <label class="form-label" for="newPassword">New Password</label>
        <input class="form-input" type="password" id="newPassword" name="newPassword" placeholder="Enter new password" required autocomplete="new-password" minlength="8" autofocus>
      </div>

      <div class="form-group">
        <label class="form-label" for="confirmPassword">Confirm Password</label>
        <input class="form-input" type="password" id="confirmPassword" name="confirmPassword" placeholder="Confirm new password" required autocomplete="new-password" minlength="8">
      </div>

      <button class="btn-primary" type="submit">Reset Password</button>
    </form>

    <p class="auth-footer-link">
      Remember your password?
      <a class="auth-link" href="${escapeAttr(env.AUTH_DOMAIN)}/login?tenant=${encodeURIComponent(tenant || '')}">Sign in</a>
    </p>

    ${clientScript}
  `;
}

/**
 * Map error codes to user-facing messages.
 */
function getErrorMessage(code: string): string {
  switch (code) {
    case 'invalid_token':
      return 'This reset link is invalid or has already been used. Please request a new one.';
    case 'token_expired':
      return 'This reset link has expired. Please request a new one.';
    case 'password_weak':
      return 'Password must be at least 8 characters.';
    case 'password_mismatch':
      return 'Passwords do not match.';
    default:
      return 'An error occurred. Please try again.';
  }
}
