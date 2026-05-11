/**
 * Platform API Client — Transactional Email Bridge
 *
 * Calls the platform-api internal fetch route
 * (`POST /api/internal/email/transactional/send`) via the PLATFORM_API
 * service binding. The fetch handler is the only dispatch path on
 * centerpiece-platform-api that can reach Cloudflare Email Sending
 * (`env.EMAIL.send_email`).
 *
 * Returns `null` when no binding is configured so callers can decide how
 * to degrade. Network/parse errors are surfaced as null so callers never
 * block user-facing flows on the email side effect.
 */
export interface TransactionalEmailInput {
  templateId: string;
  tenantId: string;
  recipient: { email: string; name?: string };
  locale?: string;
  variables: Record<string, unknown>;
  idempotencyKey?: string;
  headers?: Record<string, string>;
}

export interface TransactionalEmailResult {
  status: 'queued' | 'sent' | 'skipped';
  reason?: string;
  messageId?: string;
}

/**
 * Service-binding shape: the platform-api Worker is bound such that
 * `binding.fetch(request)` reaches its fetch handler.
 */
export interface PlatformApiEmailBinding {
  fetch(input: Request | string, init?: RequestInit): Promise<Response>;
}

const INTERNAL_URL = 'https://platform-api-internal/api/internal/email/transactional/send';

function isResult(value: unknown): value is TransactionalEmailResult {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return v.status === 'queued' || v.status === 'sent' || v.status === 'skipped';
}

export async function sendViaPlatformApi(
  binding: PlatformApiEmailBinding | undefined,
  input: TransactionalEmailInput,
): Promise<TransactionalEmailResult | null> {
  if (!binding) return null;

  try {
    const response = await binding.fetch(INTERNAL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });

    const parsed = (await response.json().catch(() => null)) as unknown;
    if (isResult(parsed)) return parsed;
    return { status: 'skipped', reason: 'invalid_response' };
  } catch (err) {
    return {
      status: 'skipped',
      reason: 'platform_api_unreachable',
      messageId: undefined,
      ...(err instanceof Error ? {} : {}),
    };
  }
}
