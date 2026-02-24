/**
 * Audit Logging
 *
 * Log all auth events for audit trail:
 * - Login success/failure
 * - Registration
 * - Password reset requests and completions
 * - OAuth callbacks
 * - Logout
 * - Rate limit hits
 *
 * Current implementation: structured console.log (captured by
 * Cloudflare Workers tail logs / Logpush).
 *
 * Future: can be extended to write to D1 audit table or external
 * logging service (e.g., Sentry, Logflare).
 */
import type { Env } from '../types.js';

export interface AuditEvent {
  /** Event type (e.g., 'login_attempt', 'register_attempt', 'password_reset_success') */
  event: string;
  /** Client IP address */
  ip: string;
  /** Request route path */
  route: string;
  /** User-Agent header */
  userAgent?: string | null;
  /** User ID (if known at the time of logging) */
  userId?: string;
  /** HTTP status code of the response */
  statusCode?: number;
  /** Additional event-specific details */
  details?: Record<string, unknown>;
}

/**
 * Log an auth event for the audit trail.
 *
 * Uses structured JSON logging so events are machine-parseable
 * in Cloudflare Workers tail logs and Logpush.
 */
export async function logAuthEvent(_env: Env, event: AuditEvent): Promise<void> {
  const logEntry = {
    type: 'AUTH_AUDIT',
    timestamp: new Date().toISOString(),
    event: event.event,
    ip: event.ip,
    route: event.route,
    userAgent: event.userAgent || null,
    userId: event.userId || null,
    statusCode: event.statusCode || null,
    details: event.details || null,
  };

  // Structured log — captured by Cloudflare Workers Logpush / tail
  console.log(JSON.stringify(logEntry));
}
