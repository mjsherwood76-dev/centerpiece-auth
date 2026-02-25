/**
 * Email HTML Template Builders
 *
 * Generates branded HTML emails for auth flows.
 * All dynamic text is HTML-escaped before insertion.
 * Inline CSS only (email clients strip <style> blocks).
 *
 * Templates:
 * - Password reset (CTA button with reset link)
 * - Welcome (greeting + login link)
 * - Password changed (security notification)
 */
import type { TenantBranding } from '../branding.js';

// ─── Types ──────────────────────────────────────────────────

export interface EmailBranding {
  storeName: string;
  logoUrl: string | null;
  primaryColor: string;
  backgroundColor: string;
}

export interface EmailContent {
  html: string;
  text: string;
  subject: string;
}

export interface PasswordResetEmailData {
  branding: EmailBranding;
  resetUrl: string;
  expiresInMinutes: number;
}

export interface WelcomeEmailData {
  branding: EmailBranding;
  userName: string;
  loginUrl: string;
}

export interface PasswordChangedEmailData {
  branding: EmailBranding;
  userEmail: string;
  changedAt: string; // ISO timestamp
  forgotPasswordUrl: string;
}

// ─── Security Utilities ─────────────────────────────────────

/**
 * Escape HTML special characters to prevent XSS in email templates.
 * Used for all user-controlled or tenant-controlled text content.
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Validate a CSS color value against accepted formats.
 * Accepts: hex (#fff, #2563eb, #2563ebff), rgb(...), hsl(...)
 * Returns the value if valid, null if invalid.
 */
export function validateCssColor(value: string): string | null {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (/^#[0-9a-fA-F]{3,8}$/.test(trimmed)) return trimmed;
  if (/^rgb\(/.test(trimmed)) return trimmed;
  if (/^hsl\(/.test(trimmed)) return trimmed;
  return null;
}

// ─── Color Extraction from TenantBranding ───────────────────

const DEFAULT_PRIMARY_COLOR = '#2563eb';
const DEFAULT_BACKGROUND_COLOR = '#ffffff';

/**
 * Extract primary and background colors from TenantBranding's CSS variables string.
 *
 * The cssVariables field is a full <style> block with `:root { --primary: ...; }` etc.
 * Brand colors in centerpiece are HSL channel values (e.g., "221 83% 53%")
 * so we convert them to proper hsl() format for email inline CSS.
 */
export function extractColorsFromBranding(tenantBranding: TenantBranding): {
  primaryColor: string;
  backgroundColor: string;
} {
  const css = tenantBranding.cssVariables;
  if (!css) {
    return { primaryColor: DEFAULT_PRIMARY_COLOR, backgroundColor: DEFAULT_BACKGROUND_COLOR };
  }

  const primary = extractCssVariable(css, '--primary');
  const background = extractCssVariable(css, '--background');

  return {
    primaryColor: primary ? toHslColor(primary) : DEFAULT_PRIMARY_COLOR,
    backgroundColor: background ? toHslColor(background) : DEFAULT_BACKGROUND_COLOR,
  };
}

/**
 * Extract a CSS variable value from the CSS variables string.
 * Looks for patterns like: --primary: 221 83% 53%;
 */
function extractCssVariable(css: string, varName: string): string | null {
  // Match the variable in the root scope (light mode)
  const pattern = new RegExp(`${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:\\s*([^;]+);`);
  const match = css.match(pattern);
  return match ? match[1].trim() : null;
}

/**
 * Convert HSL channel values (e.g., "221 83% 53%") to a proper hsl() color.
 * If already a valid CSS color (hex, rgb, hsl), return as-is.
 */
function toHslColor(value: string): string {
  // If it's already a valid CSS color, use it
  if (validateCssColor(value)) return value;
  // Check if it looks like HSL channels: "221 83% 53%"
  if (/^\d+\s+\d+%?\s+\d+%?$/.test(value.trim())) {
    return `hsl(${value.trim()})`;
  }
  return DEFAULT_PRIMARY_COLOR;
}

// ─── Shared Layout ──────────────────────────────────────────

const FONT_FAMILY = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif";

/**
 * Build the base HTML email layout with branded header and footer.
 */
function buildBaseLayout(
  content: string,
  branding: EmailBranding
): string {
  const storeName = escapeHtml(branding.storeName);
  const bgColor = validateCssColor(branding.backgroundColor) ?? DEFAULT_BACKGROUND_COLOR;
  const primaryColor = validateCssColor(branding.primaryColor) ?? DEFAULT_PRIMARY_COLOR;

  const logoHtml = branding.logoUrl
    ? `<img src="${branding.logoUrl}" alt="${storeName}" style="max-height:48px;width:auto;" />`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${storeName}</title>
</head>
<body style="margin:0;padding:0;background-color:${bgColor};font-family:${FONT_FAMILY};-webkit-font-smoothing:antialiased;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:${bgColor};">
    <tr>
      <td align="center" style="padding:24px 16px;">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:8px;overflow:hidden;">
          <!-- Header -->
          <tr>
            <td style="padding:24px 32px;border-bottom:1px solid #e5e7eb;text-align:center;">
              ${logoHtml}
              <div style="font-size:18px;font-weight:600;color:#111827;margin-top:${branding.logoUrl ? '8' : '0'}px;font-family:${FONT_FAMILY};">
                ${storeName}
              </div>
            </td>
          </tr>
          <!-- Content -->
          <tr>
            <td style="padding:32px;">
              ${content}
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding:16px 32px;border-top:1px solid #e5e7eb;text-align:center;">
              <p style="margin:0;font-size:12px;color:#6b7280;font-family:${FONT_FAMILY};">
                &copy; ${new Date().getFullYear()} ${storeName}
              </p>
              <p style="margin:4px 0 0;font-size:11px;color:#9ca3af;font-family:${FONT_FAMILY};">
                Powered by Centerpiece Lab
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

/**
 * Build a CTA button with branded primary color.
 */
function buildCtaButton(href: string, label: string, primaryColor: string): string {
  const validColor = validateCssColor(primaryColor) ?? DEFAULT_PRIMARY_COLOR;
  return `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:24px auto;">
  <tr>
    <td style="border-radius:6px;background-color:${validColor};">
      <a href="${href}" target="_blank" style="display:inline-block;padding:12px 32px;font-size:16px;font-weight:600;color:#ffffff;text-decoration:none;font-family:${FONT_FAMILY};min-height:44px;line-height:20px;">
        ${escapeHtml(label)}
      </a>
    </td>
  </tr>
</table>`;
}

// ─── Template Builders ──────────────────────────────────────

/**
 * Build the password reset email.
 */
export function buildPasswordResetEmail(data: PasswordResetEmailData): EmailContent {
  const storeName = escapeHtml(data.branding.storeName);

  const content = `
<h1 style="margin:0 0 16px;font-size:24px;font-weight:600;color:#111827;font-family:${FONT_FAMILY};">
  Reset Your Password
</h1>
<p style="margin:0 0 8px;font-size:15px;color:#374151;line-height:1.6;font-family:${FONT_FAMILY};">
  We received a request to reset your password for your ${storeName} account.
</p>
<p style="margin:0 0 24px;font-size:15px;color:#374151;line-height:1.6;font-family:${FONT_FAMILY};">
  Click the button below to set a new password. This link will expire in ${data.expiresInMinutes} minutes.
</p>
${buildCtaButton(data.resetUrl, 'Reset Password', data.branding.primaryColor)}
<p style="margin:24px 0 0;font-size:13px;color:#6b7280;line-height:1.5;font-family:${FONT_FAMILY};">
  If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.
</p>
<p style="margin:12px 0 0;font-size:12px;color:#9ca3af;word-break:break-all;font-family:${FONT_FAMILY};">
  ${escapeHtml(data.resetUrl)}
</p>`;

  const text = `Reset Your Password

We received a request to reset your password for your ${data.branding.storeName} account.

Click the link below to set a new password. This link will expire in ${data.expiresInMinutes} minutes.

${data.resetUrl}

If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.`;

  return {
    html: buildBaseLayout(content, data.branding),
    text,
    subject: `Reset your password — ${data.branding.storeName}`,
  };
}

/**
 * Build the welcome email after registration.
 */
export function buildWelcomeEmail(data: WelcomeEmailData): EmailContent {
  const storeName = escapeHtml(data.branding.storeName);
  const userName = escapeHtml(data.userName);

  const content = `
<h1 style="margin:0 0 16px;font-size:24px;font-weight:600;color:#111827;font-family:${FONT_FAMILY};">
  Welcome to ${storeName}!
</h1>
<p style="margin:0 0 8px;font-size:15px;color:#374151;line-height:1.6;font-family:${FONT_FAMILY};">
  Hi ${userName},
</p>
<p style="margin:0 0 24px;font-size:15px;color:#374151;line-height:1.6;font-family:${FONT_FAMILY};">
  Your account has been created successfully. You can now sign in and start exploring.
</p>
${buildCtaButton(data.loginUrl, 'Sign In', data.branding.primaryColor)}
<p style="margin:24px 0 0;font-size:13px;color:#6b7280;line-height:1.5;font-family:${FONT_FAMILY};">
  If you have any questions, feel free to reach out. We're happy to help!
</p>`;

  const text = `Welcome to ${data.branding.storeName}!

Hi ${data.userName},

Your account has been created successfully. You can now sign in and start exploring.

Sign in: ${data.loginUrl}

If you have any questions, feel free to reach out. We're happy to help!`;

  return {
    html: buildBaseLayout(content, data.branding),
    text,
    subject: `Welcome to ${data.branding.storeName}!`,
  };
}

/**
 * Build the password-changed security notification email.
 */
export function buildPasswordChangedEmail(data: PasswordChangedEmailData): EmailContent {
  const storeName = escapeHtml(data.branding.storeName);
  const redactedEmail = redactEmailAddress(data.userEmail);

  // Format the timestamp for display
  let changedAtDisplay: string;
  try {
    const date = new Date(data.changedAt);
    changedAtDisplay = date.toUTCString();
  } catch {
    changedAtDisplay = data.changedAt;
  }

  const content = `
<h1 style="margin:0 0 16px;font-size:24px;font-weight:600;color:#111827;font-family:${FONT_FAMILY};">
  Password Changed
</h1>
<p style="margin:0 0 8px;font-size:15px;color:#374151;line-height:1.6;font-family:${FONT_FAMILY};">
  The password for your ${storeName} account (${escapeHtml(redactedEmail)}) was successfully changed.
</p>
<p style="margin:0 0 8px;font-size:13px;color:#6b7280;line-height:1.5;font-family:${FONT_FAMILY};">
  Changed at: ${escapeHtml(changedAtDisplay)}
</p>
<div style="margin:24px 0;padding:16px;background-color:#fef3cd;border:1px solid #ffc107;border-radius:6px;">
  <p style="margin:0;font-size:14px;color:#856404;font-weight:600;font-family:${FONT_FAMILY};">
    If you did not make this change, reset your password immediately.
  </p>
</div>
${buildCtaButton(data.forgotPasswordUrl, 'Reset Password', data.branding.primaryColor)}
<p style="margin:24px 0 0;font-size:13px;color:#6b7280;line-height:1.5;font-family:${FONT_FAMILY};">
  If you made this change, no further action is required.
</p>`;

  const text = `Password Changed

The password for your ${data.branding.storeName} account (${redactedEmail}) was successfully changed.

Changed at: ${changedAtDisplay}

If you did not make this change, reset your password immediately:
${data.forgotPasswordUrl}

If you made this change, no further action is required.`;

  return {
    html: buildBaseLayout(content, data.branding),
    text,
    subject: `Password changed — ${data.branding.storeName}`,
  };
}

// ─── Helpers ────────────────────────────────────────────────

/**
 * Redact an email address for display: user@example.com → ***@example.com
 */
function redactEmailAddress(email: string): string {
  const atIndex = email.indexOf('@');
  if (atIndex <= 0) return '***';
  return `***${email.slice(atIndex)}`;
}
