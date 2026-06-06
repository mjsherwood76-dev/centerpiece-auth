/**
 * HIBP Pwned Passwords — k-anonymity range check
 *
 * Checks whether a password appears in the Have I Been Pwned breach corpus
 * using the HIBP range API (https://api.pwnedpasswords.com/range/{first5}).
 *
 * k-anonymity: only the first 5 hex characters of the SHA-1 hash are sent to
 * HIBP — the full password and full hash never leave this Worker.
 *
 * Fail-open: if HIBP is unreachable (non-200, timeout, network error), this
 * function returns `false` (not breached) and logs a structured warning event.
 * Availability > strictness for a gated site — a transient HIBP outage must
 * never block legitimate user registration or password changes.
 *
 * @see https://haveibeenpwned.com/API/v3#PwnedPasswords
 */

import type { Env } from '../types.js';

/** HIBP range endpoint base URL (no trailing slash). */
const HIBP_BASE = 'https://api.pwnedpasswords.com/range';

/** Fetch timeout in milliseconds — fail-open after this. */
const TIMEOUT_MS = 2000;

/**
 * Convert an ArrayBuffer to an uppercase hex string.
 */
function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/**
 * Check whether `password` appears in the HIBP breach corpus.
 *
 * Returns `true` if the password is known to be breached.
 * Returns `false` if it is clean, if the feature is disabled, or if HIBP is
 * unreachable (fail-open — see module doc).
 *
 * @param password - Plaintext password to check (never sent to HIBP).
 * @param env      - Worker env bindings (reads `PASSWORD_BREACH_CHECK_ENABLED`).
 */
export async function isPasswordBreached(
  password: string,
  env: Pick<Env, 'ENVIRONMENT'> & { PASSWORD_BREACH_CHECK_ENABLED?: string },
): Promise<boolean> {
  // Feature flag: off → skip check entirely (no-op).
  // Default is ON (undefined / empty treated as enabled).
  const flagRaw = env.PASSWORD_BREACH_CHECK_ENABLED;
  if (flagRaw === 'false' || flagRaw === '0') {
    return false;
  }

  // Compute SHA-1 of the password via Web Crypto (MUST use Web Crypto — no Node crypto).
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  let hashBuf: ArrayBuffer;
  try {
    hashBuf = await crypto.subtle.digest('SHA-1', data);
  } catch (err) {
    // Crypto failure (should never happen) — fail-open.
    console.warn(
      JSON.stringify({
        event: 'password.breach_check_failed',
        reason: 'sha1_error',
        error: String(err),
      }),
    );
    return false;
  }

  const fullHash = bufToHex(hashBuf); // e.g. "ABCDE12345..."
  const prefix = fullHash.slice(0, 5); // First 5 chars → sent to HIBP
  const suffix = fullHash.slice(5);    // Remaining 35 chars → compared locally

  // Fetch the range from HIBP with a short timeout.
  let responseText: string;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const resp = await fetch(`${HIBP_BASE}/${prefix}`, {
      headers: {
        'Add-Padding': 'true',   // Defeats response-size traffic analysis
        'User-Agent': 'Centerpiece-Auth/1.0 (+https://centerpiecelab.com)',
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!resp.ok) {
      // Non-200 → fail-open + log.
      console.warn(
        JSON.stringify({
          event: 'password.breach_check_failed',
          reason: 'hibp_non_200',
          status: resp.status,
        }),
      );
      return false;
    }

    responseText = await resp.text();
  } catch (err) {
    // Network error or abort (timeout) → fail-open + log.
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    console.warn(
      JSON.stringify({
        event: 'password.breach_check_failed',
        reason: isTimeout ? 'hibp_timeout' : 'hibp_network_error',
        error: String(err),
      }),
    );
    return false;
  }

  // Parse HIBP response: each line is "SUFFIX:COUNT".
  // Return true iff our suffix appears with count > 0.
  const lines = responseText.split('\r\n');
  for (const line of lines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx < 0) continue;
    const lineSuffix = line.slice(0, colonIdx).toUpperCase();
    if (lineSuffix === suffix) {
      const count = parseInt(line.slice(colonIdx + 1), 10);
      return count > 0;
    }
  }

  // Suffix not found → password is not in the breach corpus.
  return false;
}
