/**
 * Auth Page HTML Renderer
 *
 * Renders the document shell for auth pages (login, register, reset-password).
 * Uses template-string HTML — no React SSR — matching the runtime pattern
 * in centerpiece-site-runtime/src/core/PageRenderer.ts.
 *
 * Features:
 * - Tenant-branded CSS variables (light + dark mode)
 * - Tenant logo in simplified header
 * - FOUC prevention script
 * - Dark mode toggle
 * - Responsive layout, accessible markup
 * - Simplified header (logo + store name, no navigation)
 * - Footer (copyright only)
 */
import type { TenantBranding } from '../branding.js';

export interface AuthPageContent {
  /** Page title suffix (e.g., "Sign In", "Create Account") */
  title: string;
  /** Main form content HTML */
  body: string;
}

/**
 * Render a complete HTML document for an auth page.
 */
export function renderAuthPage(branding: TenantBranding, content: AuthPageContent): string {
  const pageTitle = `${content.title} — ${escapeHtml(branding.storeName)}`;

  return `<!DOCTYPE html>
<html lang="en" data-mode="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${pageTitle}</title>
  <meta name="robots" content="noindex, nofollow">
  ${branding.googleFontsLinks}
  <style>
${branding.cssVariables}

/* ─── Auth Page Base Styles ─── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html {
  font-family: var(--font-sans, system-ui, -apple-system, sans-serif);
  font-weight: var(--font-body-weight, 400);
  font-size: 16px;
  line-height: 1.5;
  color: hsl(var(--foreground));
  background: hsl(var(--background));
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* ─── Header ─── */
.auth-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem 1.5rem;
  border-bottom: 1px solid hsl(var(--border));
  background: hsl(var(--background));
}

.auth-header__brand {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  text-decoration: none;
  color: hsl(var(--foreground));
}

.auth-header__logo {
  height: 32px;
  width: auto;
  border-radius: var(--radius-sm, 4px);
}

.auth-header__name {
  font-family: var(--font-heading, var(--font-sans, system-ui));
  font-weight: var(--font-heading-weight, 600);
  font-size: 1.125rem;
  letter-spacing: -0.01em;
}

/* ─── Dark Mode Toggle ─── */
.mode-toggle {
  appearance: none;
  background: none;
  border: 1px solid hsl(var(--border));
  border-radius: var(--radius-sm, 4px);
  padding: 0.5rem;
  cursor: pointer;
  color: hsl(var(--foreground));
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background var(--motion-fast, 150ms) var(--motion-ease, ease),
              border-color var(--motion-fast, 150ms) var(--motion-ease, ease);
}

.mode-toggle:hover {
  background: hsl(var(--muted));
}

.mode-toggle:focus-visible {
  outline: 2px solid hsl(var(--ring));
  outline-offset: 2px;
}

.mode-toggle .icon-sun { display: none; }
.mode-toggle .icon-moon { display: block; }
[data-mode="dark"] .mode-toggle .icon-sun { display: block; }
[data-mode="dark"] .mode-toggle .icon-moon { display: none; }

/* ─── Main Content ─── */
.auth-main {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem 1rem;
}

.auth-card {
  width: 100%;
  max-width: 420px;
  background: hsl(var(--background));
  border: 1px solid hsl(var(--border));
  border-radius: var(--radius-lg, 12px);
  box-shadow: var(--shadow-card, 0 1px 3px rgba(0,0,0,0.1));
  padding: 2rem;
}

.auth-card__title {
  font-family: var(--font-heading, var(--font-sans, system-ui));
  font-weight: var(--font-heading-weight, 600);
  font-size: 1.5rem;
  color: hsl(var(--foreground));
  margin-bottom: 0.25rem;
}

.auth-card__subtitle {
  font-size: 0.875rem;
  color: hsl(var(--muted-foreground));
  margin-bottom: 1.5rem;
}

/* ─── Forms ─── */
.auth-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.form-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: hsl(var(--foreground));
}

.form-input {
  height: var(--control-height, 40px);
  padding: 0 0.75rem;
  border: 1px solid hsl(var(--border));
  border-radius: var(--radius-md, 8px);
  background: hsl(var(--background));
  color: hsl(var(--foreground));
  font-size: 0.875rem;
  font-family: inherit;
  transition: border-color var(--motion-fast, 150ms) var(--motion-ease, ease),
              box-shadow var(--motion-fast, 150ms) var(--motion-ease, ease);
}

.form-input:focus {
  outline: none;
  border-color: hsl(var(--ring));
  box-shadow: 0 0 0 3px hsl(var(--ring) / 0.2);
}

.form-input::placeholder {
  color: hsl(var(--muted-foreground));
}

/* ─── Buttons ─── */
.btn-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: var(--control-height, 40px);
  padding: 0 1.5rem;
  border: none;
  border-radius: var(--button-radius, 8px);
  background: hsl(var(--primary));
  color: hsl(var(--primary-foreground));
  font-size: 0.875rem;
  font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  transition: opacity var(--motion-fast, 150ms) var(--motion-ease, ease),
              transform var(--motion-fast, 150ms) var(--motion-ease, ease);
}

.btn-primary:hover {
  opacity: 0.9;
}

.btn-primary:active {
  transform: scale(0.98);
}

.btn-primary:focus-visible {
  outline: 2px solid hsl(var(--ring));
  outline-offset: 2px;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* ─── Divider ─── */
.auth-divider {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin: 0.5rem 0;
}

.auth-divider::before,
.auth-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: hsl(var(--border));
}

.auth-divider__text {
  font-size: 0.75rem;
  color: hsl(var(--muted-foreground));
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

/* ─── OAuth Buttons ─── */
.oauth-buttons {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.btn-oauth {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  height: var(--control-height, 40px);
  padding: 0 1rem;
  border: 1px solid hsl(var(--border));
  border-radius: var(--button-radius, 8px);
  background: hsl(var(--background));
  color: hsl(var(--foreground));
  font-size: 0.875rem;
  font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  text-decoration: none;
  transition: background var(--motion-fast, 150ms) var(--motion-ease, ease),
              border-color var(--motion-fast, 150ms) var(--motion-ease, ease);
}

.btn-oauth:hover {
  background: hsl(var(--muted));
  border-color: hsl(var(--foreground) / 0.2);
}

.btn-oauth:focus-visible {
  outline: 2px solid hsl(var(--ring));
  outline-offset: 2px;
}

.btn-oauth svg {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

/* ─── Links ─── */
.auth-link {
  color: hsl(var(--primary));
  text-decoration: none;
  font-size: 0.875rem;
  transition: opacity var(--motion-fast, 150ms) var(--motion-ease, ease);
}

.auth-link:hover {
  text-decoration: underline;
  opacity: 0.8;
}

.auth-link:focus-visible {
  outline: 2px solid hsl(var(--ring));
  outline-offset: 2px;
  border-radius: 2px;
}

.auth-footer-link {
  text-align: center;
  font-size: 0.875rem;
  color: hsl(var(--muted-foreground));
  margin-top: 1rem;
}

.auth-forgot {
  text-align: right;
  margin-top: -0.5rem;
}

/* ─── Error Message ─── */
.auth-error {
  padding: 0.75rem 1rem;
  border-radius: var(--radius-md, 8px);
  background: hsl(var(--destructive) / 0.1);
  color: hsl(var(--destructive));
  font-size: 0.875rem;
  display: none;
}

.auth-error[data-visible="true"] {
  display: block;
}

/* ─── Success Message ─── */
.auth-success {
  padding: 0.75rem 1rem;
  border-radius: var(--radius-md, 8px);
  background: hsl(142 76% 36% / 0.1);
  color: hsl(142 76% 36%);
  font-size: 0.875rem;
  display: none;
}

.auth-success[data-visible="true"] {
  display: block;
}

/* ─── Footer ─── */
.auth-footer {
  padding: 1rem 1.5rem;
  text-align: center;
  font-size: 0.75rem;
  color: hsl(var(--muted-foreground));
  border-top: 1px solid hsl(var(--border));
}

/* ─── Responsive ─── */
@media (max-width: 480px) {
  .auth-card {
    border: none;
    border-radius: 0;
    box-shadow: none;
    padding: 1.5rem 1rem;
  }

  .auth-main {
    align-items: flex-start;
    padding-top: 1rem;
  }
}
  </style>
  <script>
    // FOUC prevention: apply stored dark mode preference immediately
    (function() {
      try {
        var mode = localStorage.getItem('cp-auth-mode');
        if (mode === 'dark' || (!mode && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
          document.documentElement.setAttribute('data-mode', 'dark');
        }
      } catch(e) {}
    })();
  </script>
</head>
<body>
  <!-- Header -->
  <header class="auth-header">
    <span class="auth-header__brand">
      ${branding.logoUrl ? `<img class="auth-header__logo" src="${escapeAttr(branding.logoUrl)}" alt="${escapeAttr(branding.storeName)} logo">` : ''}
      <span class="auth-header__name">${escapeHtml(branding.storeName)}</span>
    </span>
    <button class="mode-toggle" type="button" aria-label="Toggle dark mode" title="Toggle dark mode">
      <svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      <svg class="icon-sun" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
    </button>
  </header>

  <!-- Main Content -->
  <main class="auth-main">
    <div class="auth-card">
      ${content.body}
    </div>
  </main>

  <!-- Footer -->
  <footer class="auth-footer">
    &copy; ${new Date().getFullYear()} ${escapeHtml(branding.storeName)}. All rights reserved.
  </footer>

  <!-- Dark Mode Toggle Script -->
  <script>
    (function() {
      var toggle = document.querySelector('.mode-toggle');
      if (!toggle) return;
      toggle.addEventListener('click', function() {
        var html = document.documentElement;
        var current = html.getAttribute('data-mode');
        var next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-mode', next);
        try { localStorage.setItem('cp-auth-mode', next); } catch(e) {}
      });
    })();
  </script>
</body>
</html>`;
}

// ─── SVG Icons for OAuth Providers ──────────────────────────

export const oauthIcons = {
  google: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>',
  facebook: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" fill="#1877F2"/></svg>',
  apple: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M17.05 20.28c-.98.95-2.05.88-3.08.4-1.09-.5-2.08-.48-3.24 0-1.44.62-2.2.44-3.06-.4C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z" fill="currentColor"/></svg>',
  microsoft: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><rect x="1" y="1" width="10" height="10" fill="#F25022"/><rect x="13" y="1" width="10" height="10" fill="#7FBA00"/><rect x="1" y="13" width="10" height="10" fill="#00A4EF"/><rect x="13" y="13" width="10" height="10" fill="#FFB900"/></svg>',
};

// ─── Utilities ──────────────────────────────────────────────

/** Escape HTML entities to prevent XSS. */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/** Escape a string for use in an HTML attribute. */
export function escapeAttr(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
