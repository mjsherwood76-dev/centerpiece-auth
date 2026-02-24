/**
 * GET /.well-known/jwks.json — JWKS endpoint for JWT verification.
 *
 * Returns the public key in JWK format so that other Workers
 * (e.g. centerpiece-site-runtime) can verify access tokens
 * without a shared secret.
 *
 * Uses ES256 (ECDSA P-256) key pair.
 */
import type { Env } from '../types.js';

/** Cached JWK response per isolate (avoids re-importing on every request). */
let cachedJwksResponse: { body: string; etag: string } | null = null;

export async function handleJWKS(env: Env): Promise<Response> {
  if (cachedJwksResponse) {
    return new Response(cachedJwksResponse.body, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=3600',
        ETag: cachedJwksResponse.etag,
      },
    });
  }

  try {
    const publicKeyPem = atob(env.JWT_PUBLIC_KEY);

    // Import the PEM public key
    const keyData = pemToArrayBuffer(publicKeyPem);
    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      keyData,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // extractable — needed to export as JWK
      ['verify']
    );

    // Export as JWK
    const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);

    const jwks = {
      keys: [
        {
          ...jwk,
          kid: 'v1',
          alg: 'ES256',
          use: 'sig',
        },
      ],
    };

    const body = JSON.stringify(jwks);
    const etag = `"${await sha256Hex(body)}"`;
    cachedJwksResponse = { body, etag };

    return new Response(body, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=3600',
        ETag: etag,
      },
    });
  } catch (err) {
    console.error('JWKS generation failed:', err);
    return new Response(JSON.stringify({ error: 'Failed to generate JWKS' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Convert PEM-encoded key to ArrayBuffer (strip header/footer + base64-decode).
 */
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const lines = pem
    .replace(/-----BEGIN [A-Z ]+-----/, '')
    .replace(/-----END [A-Z ]+-----/, '')
    .replace(/\s/g, '');
  const binary = atob(lines);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * SHA-256 hex digest for ETag generation.
 */
async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}
