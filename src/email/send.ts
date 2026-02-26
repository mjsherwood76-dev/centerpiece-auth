/**
 * High-Level Email Send Functions
 *
 * Non-blocking wrappers around SendGrid client + templates.
 * Each function:
 * - NEVER throws — catches all errors internally
 * - Logs structured JSON via ConsoleJsonLogger for observability
 * - Gracefully degrades when SENDGRID_API_KEY is not configured
 * - Redacts email addresses in logs
 */
import type { Env } from '../types.js';
import type { TenantBranding } from '../branding.js';
import type { Logger } from '../core/logger.js';
import { sendViaSendGrid } from './sendgridClient.js';
import {
  buildPasswordResetEmail,
  buildWelcomeEmail,
  buildPasswordChangedEmail,
  extractColorsFromBranding,
  type EmailBranding,
} from './templates.js';

// ─── Log Helpers ────────────────────────────────────────────

type EmailType = 'password_reset' | 'welcome' | 'password_changed';

interface EmailLogEvent {
  event: 'email.sent' | 'email.failed' | 'email.skipped';
  type: EmailType;
  to: string; // Redacted: ***@domain.com
  statusCode?: number;
  error?: string;
  failureClass?: 'transient' | 'permanent';
  tenantId?: string;
  userId?: string;
  reason?: string;
}

function redactEmail(email: string): string {
  const atIndex = email.indexOf('@');
  if (atIndex <= 0) return '***';
  return `***${email.slice(atIndex)}`;
}

function logEmailEvent(
  logger: Logger | null,
  correlationId: string,
  logEvent: EmailLogEvent,
): void {
  if (logger) {
    const level = logEvent.event === 'email.failed' ? 'error' : 'info';
    logger[level]({
      correlationId,
      event: logEvent.event,
      type: logEvent.type,
      to: logEvent.to,
      ...(logEvent.statusCode != null ? { statusCode: logEvent.statusCode } : {}),
      ...(logEvent.error ? { error: logEvent.error } : {}),
      ...(logEvent.failureClass ? { failureClass: logEvent.failureClass } : {}),
      ...(logEvent.tenantId ? { tenantId: logEvent.tenantId } : {}),
      ...(logEvent.userId ? { userId: logEvent.userId } : {}),
      ...(logEvent.reason ? { reason: logEvent.reason } : {}),
    });
  } else {
    // Fallback for callers that haven't been updated yet
    console.log(JSON.stringify(logEvent));
  }
}

// ─── Branding Helpers ───────────────────────────────────────

function buildEmailBranding(branding: TenantBranding): EmailBranding {
  const colors = extractColorsFromBranding(branding);
  return {
    storeName: branding.storeName,
    logoUrl: branding.logoUrl,
    primaryColor: colors.primaryColor,
    backgroundColor: colors.backgroundColor,
  };
}

// ─── Send Functions ─────────────────────────────────────────

/**
 * Send a password reset email.
 * Non-blocking: logs failure but never throws.
 */
export async function sendPasswordResetEmail(
  env: Env,
  to: string,
  resetUrl: string,
  branding: TenantBranding,
  context?: { tenantId?: string; userId?: string; logger?: Logger; correlationId?: string }
): Promise<void> {
  const emailType: EmailType = 'password_reset';
  const redacted = redactEmail(to);
  const logger = context?.logger ?? null;
  const correlationId = context?.correlationId ?? 'unknown';

  if (!env.SENDGRID_API_KEY) {
    logEmailEvent(logger, correlationId, {
      event: 'email.skipped',
      type: emailType,
      to: redacted,
      reason: 'SENDGRID_API_KEY not configured',
      tenantId: context?.tenantId,
      userId: context?.userId,
    });
    return;
  }

  try {
    const emailBranding = buildEmailBranding(branding);

    // Derive expiry from the token TTL config (default 3600s = 60 minutes)
    const expiresInMinutes = 60;

    const emailContent = buildPasswordResetEmail({
      branding: emailBranding,
      resetUrl,
      expiresInMinutes,
    });

    const result = await sendViaSendGrid(env.SENDGRID_API_KEY, {
      to: { email: to },
      from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
      subject: emailContent.subject,
      html: emailContent.html,
      text: emailContent.text,
    });

    if (result.success) {
      logEmailEvent(logger, correlationId, {
        event: 'email.sent',
        type: emailType,
        to: redacted,
        statusCode: result.statusCode,
        tenantId: context?.tenantId,
        userId: context?.userId,
      });
    } else {
      logEmailEvent(logger, correlationId, {
        event: 'email.failed',
        type: emailType,
        to: redacted,
        statusCode: result.statusCode,
        error: result.error,
        failureClass: result.failureClass,
        tenantId: context?.tenantId,
        userId: context?.userId,
      });
    }
  } catch (err) {
    logEmailEvent(logger, correlationId, {
      event: 'email.failed',
      type: emailType,
      to: redacted,
      error: err instanceof Error ? err.message : 'Unknown error',
      tenantId: context?.tenantId,
      userId: context?.userId,
    });
  }
}

/**
 * Send a welcome email after registration.
 * Non-blocking: logs failure but never throws.
 */
export async function sendWelcomeEmail(
  env: Env,
  to: string,
  userName: string,
  loginUrl: string,
  branding: TenantBranding,
  context?: { tenantId?: string; userId?: string; logger?: Logger; correlationId?: string }
): Promise<void> {
  const emailType: EmailType = 'welcome';
  const redacted = redactEmail(to);
  const logger = context?.logger ?? null;
  const correlationId = context?.correlationId ?? 'unknown';

  if (!env.SENDGRID_API_KEY) {
    logEmailEvent(logger, correlationId, {
      event: 'email.skipped',
      type: emailType,
      to: redacted,
      reason: 'SENDGRID_API_KEY not configured',
      tenantId: context?.tenantId,
      userId: context?.userId,
    });
    return;
  }

  try {
    const emailBranding = buildEmailBranding(branding);

    const emailContent = buildWelcomeEmail({
      branding: emailBranding,
      userName,
      loginUrl,
    });

    const result = await sendViaSendGrid(env.SENDGRID_API_KEY, {
      to: { email: to },
      from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
      subject: emailContent.subject,
      html: emailContent.html,
      text: emailContent.text,
    });

    if (result.success) {
      logEmailEvent(logger, correlationId, {
        event: 'email.sent',
        type: emailType,
        to: redacted,
        statusCode: result.statusCode,
        tenantId: context?.tenantId,
        userId: context?.userId,
      });
    } else {
      logEmailEvent(logger, correlationId, {
        event: 'email.failed',
        type: emailType,
        to: redacted,
        statusCode: result.statusCode,
        error: result.error,
        failureClass: result.failureClass,
        tenantId: context?.tenantId,
        userId: context?.userId,
      });
    }
  } catch (err) {
    logEmailEvent(logger, correlationId, {
      event: 'email.failed',
      type: emailType,
      to: redacted,
      error: err instanceof Error ? err.message : 'Unknown error',
      tenantId: context?.tenantId,
      userId: context?.userId,
    });
  }
}

/**
 * Send a password-changed security notification.
 * Non-blocking: logs failure but never throws.
 */
export async function sendPasswordChangedEmail(
  env: Env,
  to: string,
  branding: TenantBranding,
  forgotPasswordUrl: string,
  context?: { tenantId?: string; userId?: string; logger?: Logger; correlationId?: string }
): Promise<void> {
  const emailType: EmailType = 'password_changed';
  const redacted = redactEmail(to);
  const logger = context?.logger ?? null;
  const correlationId = context?.correlationId ?? 'unknown';

  if (!env.SENDGRID_API_KEY) {
    logEmailEvent(logger, correlationId, {
      event: 'email.skipped',
      type: emailType,
      to: redacted,
      reason: 'SENDGRID_API_KEY not configured',
      tenantId: context?.tenantId,
      userId: context?.userId,
    });
    return;
  }

  try {
    const emailBranding = buildEmailBranding(branding);

    const emailContent = buildPasswordChangedEmail({
      branding: emailBranding,
      userEmail: to,
      changedAt: new Date().toISOString(),
      forgotPasswordUrl,
    });

    const result = await sendViaSendGrid(env.SENDGRID_API_KEY, {
      to: { email: to },
      from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
      subject: emailContent.subject,
      html: emailContent.html,
      text: emailContent.text,
    });

    if (result.success) {
      logEmailEvent(logger, correlationId, {
        event: 'email.sent',
        type: emailType,
        to: redacted,
        statusCode: result.statusCode,
        tenantId: context?.tenantId,
        userId: context?.userId,
      });
    } else {
      logEmailEvent(logger, correlationId, {
        event: 'email.failed',
        type: emailType,
        to: redacted,
        statusCode: result.statusCode,
        error: result.error,
        failureClass: result.failureClass,
        tenantId: context?.tenantId,
        userId: context?.userId,
      });
    }
  } catch (err) {
    logEmailEvent(logger, correlationId, {
      event: 'email.failed',
      type: emailType,
      to: redacted,
      error: err instanceof Error ? err.message : 'Unknown error',
      tenantId: context?.tenantId,
      userId: context?.userId,
    });
  }
}
