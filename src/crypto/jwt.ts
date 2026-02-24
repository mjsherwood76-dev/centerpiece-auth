/**
 * JWT Utilities — ES256 (ECDSA P-256)
 *
 * Sign and verify JWT access tokens using the Web Crypto API.
 * Auth Worker signs with private key; runtime verifies via JWKS endpoint.
 *
 * JWT payload:
 *   { sub, email, name, aud, iss, kid, iat, exp }
 *
 * No external dependencies — uses native `crypto.subtle`.
 */

// ─── Types ──────────────────────────────────────────────────

export interface JwtPayload {
  sub: string; // userId
  email: string;
  name: string;
  aud: 'storefront' | 'admin';
  iss: string; // AUTH_DOMAIN
  iat: number; // issued at (Unix seconds)
  exp: number; // expiration (Unix seconds)
}

export interface JwtHeader {
  alg: 'ES256';
  typ: 'JWT';
  kid: string;
}

// ─── Key ID ─────────────────────────────────────────────────

/** Current key identifier for rotation support. */
const CURRENT_KID = 'v1';

// ─── Sign ───────────────────────────────────────────────────

/**
 * Sign a JWT with ES256 (ECDSA P-256) using the private key.
 *
 * @param payload - Claims to include in the JWT
 * @param privateKeyBase64 - Base64-encoded PEM private key from `JWT_PRIVATE_KEY` secret
 * @returns Signed JWT string (header.payload.signature)
 */
export async function signJwt(
  payload: Omit<JwtPayload, 'iat' | 'exp'>,
  privateKeyBase64: string,
  ttlSeconds: number
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const header: JwtHeader = {
    alg: 'ES256',
    typ: 'JWT',
    kid: CURRENT_KID,
  };

  const fullPayload: JwtPayload = {
    ...payload,
    iat: now,
    exp: now + ttlSeconds,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // Import private key
  const privateKey = await importPrivateKey(privateKeyBase64);

  // Sign
  const signatureBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(signingInput)
  );

  const encodedSignature = base64UrlEncodeBuffer(new Uint8Array(signatureBuffer));

  return `${signingInput}.${encodedSignature}`;
}

// ─── Verify ─────────────────────────────────────────────────

/**
 * Verify a JWT signature and decode the payload.
 *
 * @param token - JWT string
 * @param publicKeyBase64 - Base64-encoded PEM public key from `JWT_PUBLIC_KEY` secret
 * @returns Decoded payload if valid, null if invalid
 */
export async function verifyJwt(
  token: string,
  publicKeyBase64: string
): Promise<JwtPayload | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  // Decode and validate header
  let header: JwtHeader;
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader));
  } catch {
    return null;
  }

  if (header.alg !== 'ES256' || header.typ !== 'JWT') return null;

  // Decode payload
  let payload: JwtPayload;
  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload));
  } catch {
    return null;
  }

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) return null;

  // Import public key
  const publicKey = await importPublicKey(publicKeyBase64);

  // Verify signature
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signatureBytes = base64UrlDecodeBuffer(encodedSignature);

  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signatureBytes.buffer as ArrayBuffer,
    new TextEncoder().encode(signingInput)
  );

  if (!valid) return null;

  return payload;
}

// ─── Key Import Helpers ─────────────────────────────────────

/**
 * Import a base64-encoded PEM private key for ES256 signing.
 */
async function importPrivateKey(base64Pem: string): Promise<CryptoKey> {
  const pem = atob(base64Pem);
  const keyData = pemToArrayBuffer(pem, 'PRIVATE');
  return crypto.subtle.importKey(
    'pkcs8',
    keyData,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
}

/**
 * Import a base64-encoded PEM public key for ES256 verification.
 */
async function importPublicKey(base64Pem: string): Promise<CryptoKey> {
  const pem = atob(base64Pem);
  const keyData = pemToArrayBuffer(pem, 'PUBLIC');
  return crypto.subtle.importKey(
    'spki',
    keyData,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

/**
 * Convert PEM-encoded key to ArrayBuffer.
 */
function pemToArrayBuffer(pem: string, type: 'PRIVATE' | 'PUBLIC'): ArrayBuffer {
  const header = type === 'PRIVATE' ? '-----BEGIN PRIVATE KEY-----' : '-----BEGIN PUBLIC KEY-----';
  const footer = type === 'PRIVATE' ? '-----END PRIVATE KEY-----' : '-----END PUBLIC KEY-----';
  const lines = pem.replace(header, '').replace(footer, '').replace(/\s/g, '');
  const binary = atob(lines);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ─── Base64url Helpers ──────────────────────────────────────

function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): string {
  // Restore standard base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';
  return atob(base64);
}

function base64UrlEncodeBuffer(buffer: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecodeBuffer(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ─── SHA-256 Hashing ────────────────────────────────────────

/**
 * Compute SHA-256 hash of a string, returned as hex.
 * Used for hashing auth codes and refresh tokens before storage.
 */
export async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
