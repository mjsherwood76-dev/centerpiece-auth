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
 * Uses ConsoleJsonLogger for structured JSON output with correlation IDs.
 * All events are prefixed with `auth.audit.` for easy filtering in
 * Workers Observability and Logpush.
 */
import type { Logger } from '../core/logger.js';

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
  /** Correlation ID for request tracing */
  correlationId?: string;
  /** Additional event-specific details */
  details?: Record<string, unknown>;
}

/**
 * Log an auth event for the audit trail.
 *
 * Uses structured JSON logger so events are machine-parseable
 * in Cloudflare Workers Observability and Logpush.
 */
export function logAuthEvent(logger: Logger, event: AuditEvent): void {
  logger.info({
    correlationId: event.correlationId || 'unknown',
    event: `auth.audit.${event.event}`,
    ip: event.ip,
    route: event.route,
    userAgent: event.userAgent || null,
    userId: event.userId || null,
    statusCode: event.statusCode || null,
    details: event.details || null,
  });
}
