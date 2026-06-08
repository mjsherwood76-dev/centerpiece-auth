/**
 * Invite Token Utilities (Fix_Team_Invites, ADR 020)
 *
 * Single-use team-invite tokens: 32 random bytes encoded base64url (no padding),
 * delivered only in the invite email URL. Only the SHA-256 hex hash is stored at
 * rest (`tenant_invites.token_hash`) — the plaintext token is never persisted.
 * Lookup is by hash; the hash-keyed index lookup is the constant-time-equivalent
 * compare (an attacker cannot enumerate by timing).
 */
import { sha256Hex } from './jwt.js';

/** Invite token byte length (256-bit random). */
const INVITE_TOKEN_BYTES = 32;

/** Encode bytes as base64url without padding. */
function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Generate a cryptographically random invite token (base64url, no padding).
 * The returned string is the PLAINTEXT token — send it in the email URL only,
 * never store it. Store `hashInviteToken(token)` instead.
 */
export function generateInviteToken(): string {
  const bytes = new Uint8Array(INVITE_TOKEN_BYTES);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

/**
 * Hash an invite token for storage / lookup. Always store the SHA-256 hash,
 * never the plaintext token.
 */
export async function hashInviteToken(token: string): Promise<string> {
  return sha256Hex(token);
}
