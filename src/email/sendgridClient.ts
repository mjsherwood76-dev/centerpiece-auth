/**
 * SendGrid HTTP API v3 Client
 *
 * Minimal fetch-based client for transactional email sending.
 * No npm dependencies — uses native fetch() available in Cloudflare Workers.
 *
 * Features:
 * - Never throws — returns success/failure result objects
 * - Single retry for transient errors (429, 5xx) with random jitter
 * - 10-second timeout per attempt
 */

// ─── Types ──────────────────────────────────────────────────

export interface SendGridMessage {
  to: { email: string; name?: string };
  from: { email: string; name?: string };
  replyTo?: { email: string; name?: string };
  subject: string;
  html: string;
  text?: string; // Plain text fallback
}

export interface SendGridResult {
  success: boolean;
  statusCode: number;
  error?: string;
  failureClass?: 'transient' | 'permanent';
}

// ─── Constants ──────────────────────────────────────────────

const SENDGRID_API_URL = 'https://api.sendgrid.com/v3/mail/send';
const REQUEST_TIMEOUT_MS = 10_000;
const MIN_RETRY_DELAY_MS = 250;
const MAX_RETRY_DELAY_MS = 750;

// ─── Public API ─────────────────────────────────────────────

/**
 * Send an email via SendGrid API v3.
 *
 * @returns Result with success/failure status. Never throws — caller handles logging.
 */
export async function sendViaSendGrid(
  apiKey: string,
  message: SendGridMessage
): Promise<SendGridResult> {
  const result = await attemptSend(apiKey, message);

  // Retry once for transient errors (429 or 5xx)
  if (!result.success && result.failureClass === 'transient') {
    const jitter = MIN_RETRY_DELAY_MS + Math.random() * (MAX_RETRY_DELAY_MS - MIN_RETRY_DELAY_MS);
    await sleep(jitter);
    return attemptSend(apiKey, message);
  }

  return result;
}

// ─── Internal ───────────────────────────────────────────────

async function attemptSend(
  apiKey: string,
  message: SendGridMessage
): Promise<SendGridResult> {
  try {
    const body = buildRequestBody(message);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(SENDGRID_API_URL, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      // 202 Accepted = success (SendGrid queued the email)
      if (response.status === 202) {
        return { success: true, statusCode: 202 };
      }

      // Classify failure
      const failureClass = classifyFailure(response.status);
      let errorText: string;
      try {
        errorText = await response.text();
      } catch {
        errorText = `HTTP ${response.status}`;
      }

      return {
        success: false,
        statusCode: response.status,
        error: errorText.slice(0, 500), // Truncate long error bodies
        failureClass,
      };
    } finally {
      clearTimeout(timeout);
    }
  } catch (err) {
    // Network error, timeout, or AbortError
    const message_str = err instanceof Error ? err.message : 'Unknown fetch error';
    return {
      success: false,
      statusCode: 0,
      error: message_str,
      failureClass: 'transient',
    };
  }
}

/**
 * Build the SendGrid v3 API request body.
 */
function buildRequestBody(message: SendGridMessage): Record<string, unknown> {
  const body: Record<string, unknown> = {
    personalizations: [
      {
        to: [message.to],
      },
    ],
    from: message.from,
    subject: message.subject,
    content: [
      // Plain text first (fallback), then HTML
      ...(message.text
        ? [{ type: 'text/plain', value: message.text }]
        : []),
      { type: 'text/html', value: message.html },
    ],
  };

  if (message.replyTo) {
    body.reply_to = message.replyTo;
  }

  return body;
}

/**
 * Classify an HTTP status code as transient or permanent failure.
 */
function classifyFailure(status: number): 'transient' | 'permanent' {
  if (status === 429 || status >= 500) {
    return 'transient';
  }
  return 'permanent';
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
