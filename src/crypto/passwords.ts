/**
 * Password Hashing & Verification
 *
 * Uses PBKDF2-SHA-256 via Web Crypto API (`crypto.subtle`),
 * which is available in Cloudflare Workers with `nodejs_compat`.
 *
 * No external dependencies required.
 *
 * Format: `pbkdf2:iterations:salt_hex:hash_hex`
 */

/**
 * Number of PBKDF2 iterations.
 * Cloudflare Workers limits PBKDF2 to 100,000 iterations max.
 * This is still strong when combined with 32-byte random salts.
 */
const ITERATIONS = 100_000;
const SALT_LENGTH = 32; // bytes
const KEY_LENGTH = 32; // bytes (256 bits)

/**
 * Hash a password using PBKDF2-SHA-256.
 *
 * @param password - Plaintext password
 * @returns Encoded hash string: `pbkdf2:iterations:salt_hex:hash_hex`
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = new Uint8Array(SALT_LENGTH);
  crypto.getRandomValues(salt);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    KEY_LENGTH * 8 // bits
  );

  const hashHex = bufferToHex(new Uint8Array(derivedBits));
  const saltHex = bufferToHex(salt);

  return `pbkdf2:${ITERATIONS}:${saltHex}:${hashHex}`;
}

/**
 * Verify a password against a stored hash.
 *
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param password - Plaintext password to verify
 * @param storedHash - Encoded hash string from `hashPassword()`
 * @returns true if the password matches
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split(':');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') {
    return false;
  }

  const iterations = parseInt(parts[1], 10);
  const salt = hexToBuffer(parts[2]);
  const expectedHash = hexToBuffer(parts[3]);

  if (isNaN(iterations) || iterations < 1) {
    return false;
  }

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    expectedHash.length * 8 // bits
  );

  const derivedArray = new Uint8Array(derivedBits);

  // Constant-time comparison
  return constantTimeEqual(derivedArray, expectedHash);
}

// ─── Utility Functions ──────────────────────────────────────

/**
 * Constant-time comparison of two byte arrays.
 * Prevents timing side-channel attacks on hash comparison.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

function bufferToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuffer(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
