/**
 * Signed Consent-Request Tokens — HMAC-SHA-256
 *
 * The third-party OAuth consent screen (GET /oauth/authorize) renders an
 * Allow/Deny form that POSTs back to /oauth/authorize/decision. The original,
 * already-validated authorize request must survive that round trip WITHOUT the
 * decision endpoint trusting any re-submitted query params — otherwise a forged
 * POST could swap in a different client_id, redirect_uri, or scope set after the
 * seller looked at the consent screen.
 *
 * We solve this by embedding the validated request as a compact HMAC-signed
 * token (`payload_b64url.signature_b64url`). The decision handler verifies the
 * signature and the embedded expiry before acting — the params are tamper-proof
 * and the handler re-derives everything it needs from the verified payload, not
 * from the request body.
 *
 * The token also carries:
 * - `uid`: the logged-in seller's user_id at consent-render time. The decision
 *   handler re-checks the live session and rejects if the session user changed.
 * - `csrf`: a random nonce. The form also submits it as a separate body field;
 *   the handler requires the two to match (double-submit CSRF defence).
 *
 * Keyed by `INTERNAL_SECRET` (a server-only secret already in env). This is an
 * internal integrity check between two endpoints of the SAME worker — not a
 * cross-service or user-facing token — so a symmetric HMAC is appropriate here
 * (the ES256 JWT path remains the mechanism for issued access tokens).
 *
 * @module crypto/signedRequest
 */

// ─── Payload shape ──────────────────────────────────────────

export interface ConsentRequestPayload {
  /** Third-party OAuth client_id. */
  clientId: string;
  /** Exact, allow-list-validated redirect URI. */
  redirectUri: string;
  /** Requested + granted scopes (already validated ⊆ client allowed scopes). */
  scopes: string[];
  /** PKCE S256 challenge supplied by the client. */
  codeChallenge: string;
  /** Opaque client state echoed back on redirect. */
  state: string;
  /** Logged-in seller user_id at consent-render time. */
  uid: string;
  /** CSRF nonce — must be echoed by the decision form. */
  csrf: string;
  /** Expiry (Unix seconds). The consent screen is short-lived. */
  exp: number;
}

// ─── Base64url helpers ──────────────────────────────────────

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ─── HMAC ───────────────────────────────────────────────────

async function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

/**
 * Sign a consent-request payload. Returns `payload_b64url.signature_b64url`.
 */
export async function signConsentRequest(
  payload: ConsentRequestPayload,
  secret: string,
): Promise<string> {
  const key = await importHmacKey(secret);
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const encodedPayload = base64UrlEncode(payloadBytes);
  const sigBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(encodedPayload));
  const encodedSig = base64UrlEncode(new Uint8Array(sigBuffer));
  return `${encodedPayload}.${encodedSig}`;
}

/**
 * Verify a signed consent-request token.
 *
 * Uses `crypto.subtle.verify` (constant-time HMAC verification) and checks the
 * embedded expiry. Returns the decoded payload on success, or null if the
 * signature is invalid, the token is malformed, or it has expired.
 *
 * @param now - Unix seconds (caller passes the request's current time)
 */
export async function verifyConsentRequest(
  token: string,
  secret: string,
  now: number,
): Promise<ConsentRequestPayload | null> {
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;

  const encodedPayload = token.slice(0, dot);
  const encodedSig = token.slice(dot + 1);

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(encodedSig);
  } catch {
    return null;
  }

  const key = await importHmacKey(secret);
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes.buffer as ArrayBuffer,
    new TextEncoder().encode(encodedPayload),
  );
  if (!valid) return null;

  let payload: ConsentRequestPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(encodedPayload))) as ConsentRequestPayload;
  } catch {
    return null;
  }

  if (typeof payload.exp !== 'number' || payload.exp <= now) return null;

  return payload;
}

/**
 * Generate a random CSRF nonce (16-byte hex).
 */
export function generateCsrfToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Constant-time string comparison for CSRF token matching.
 */
export function constantTimeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}
