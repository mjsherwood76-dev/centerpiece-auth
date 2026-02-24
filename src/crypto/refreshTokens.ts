/**
 * Refresh Token Utilities
 *
 * Generate, hash, and manage refresh tokens with family-based
 * rotation and theft detection.
 *
 * - Generate cryptographically random tokens (`crypto.getRandomValues`)
 * - Store hash in D1 (never store plaintext)
 * - Refresh token TTL: 30 days
 * - Rotation: old token revoked, new one issued in same `family_id`
 * - Reuse detection: revoked token presented → revoke entire family
 * - Record `ip` and `user_agent` at creation for audit
 */
import { sha256Hex } from './jwt.js';

/** Refresh token byte length (256-bit random). */
const TOKEN_BYTE_LENGTH = 32;

/**
 * Generate a cryptographically random refresh token.
 *
 * @returns Hex-encoded random token string
 */
export function generateRefreshToken(): string {
  const bytes = new Uint8Array(TOKEN_BYTE_LENGTH);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Hash a refresh token for storage.
 * Never store plaintext tokens — always store the SHA-256 hash.
 *
 * @param token - Plaintext refresh token
 * @returns SHA-256 hex hash of the token
 */
export async function hashRefreshToken(token: string): Promise<string> {
  return sha256Hex(token);
}

/**
 * Generate a new UUID v4 for token IDs and family IDs.
 */
export function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Generate a cryptographically random authorization code.
 *
 * @returns Hex-encoded random code string (256-bit)
 */
export function generateAuthCode(): string {
  const bytes = new Uint8Array(TOKEN_BYTE_LENGTH);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Hash an authorization code for storage.
 *
 * @param code - Plaintext authorization code
 * @returns SHA-256 hex hash
 */
export async function hashAuthCode(code: string): Promise<string> {
  return sha256Hex(code);
}

/**
 * Build the Set-Cookie header value for a refresh token cookie.
 *
 * Cookie properties:
 * - HttpOnly: prevents JavaScript access
 * - Secure: HTTPS only
 * - SameSite=Lax: works with top-level redirect refresh pattern
 * - Path=/: accessible across all auth domain paths
 *
 * @param token - Plaintext refresh token
 * @param maxAgeDays - Cookie max age in days
 * @param authDomain - Auth domain for cookie scope
 * @returns Set-Cookie header value
 */
export function buildRefreshCookieHeader(
  token: string,
  maxAgeDays: number,
  authDomain: string
): string {
  const maxAgeSeconds = maxAgeDays * 24 * 60 * 60;
  // Extract domain for cookie scope (remove protocol)
  const domain = new URL(authDomain).hostname;

  // In development (localhost), omit Domain and Secure attributes
  const isLocalhost = domain === 'localhost' || domain === '127.0.0.1';
  const securePart = isLocalhost ? '' : '; Secure';
  const domainPart = isLocalhost ? '' : `; Domain=${domain}`;

  return `cp_refresh=${token}; HttpOnly${securePart}; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}${domainPart}`;
}

/**
 * Build a Set-Cookie header to clear the refresh token cookie.
 */
export function buildClearRefreshCookieHeader(authDomain: string): string {
  const domain = new URL(authDomain).hostname;
  const isLocalhost = domain === 'localhost' || domain === '127.0.0.1';
  const securePart = isLocalhost ? '' : '; Secure';
  const domainPart = isLocalhost ? '' : `; Domain=${domain}`;

  return `cp_refresh=; HttpOnly${securePart}; SameSite=Lax; Path=/; Max-Age=0${domainPart}`;
}

/**
 * Extract the refresh token from the Cookie header.
 *
 * @param cookieHeader - Raw Cookie header string
 * @returns The refresh token value, or null if not present
 */
export function extractRefreshToken(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';').map((c) => c.trim());
  for (const cookie of cookies) {
    const [name, ...valueParts] = cookie.split('=');
    if (name.trim() === 'cp_refresh') {
      const value = valueParts.join('=').trim();
      return value || null;
    }
  }
  return null;
}
