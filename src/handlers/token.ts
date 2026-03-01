/**
 * Token Exchange Handler
 *
 * POST /api/token — Exchange authorization code for JWT access token
 *
 * This is a **server-to-server** endpoint (runtime Worker → auth Worker).
 * No CORS headers needed.
 *
 * Flow:
 * 1. Accept `{ code, tenant_id, redirect_origin, code_verifier? }`
 * 2. Hash the code, look up in `auth_codes` table
 * 3. Verify: not expired, tenant_id matches, redirect_origin matches
 * 4. If auth code has `code_challenge`: verify PKCE (SHA256(code_verifier) === code_challenge)
 * 5. Delete row immediately (single-use enforcement)
 * 6. Look up user details
 * 7. For admin audience: query tenant_memberships for roles + primaryTenantId
 * 8. Return signed JWT access token
 *
 * Security:
 * - Code stored as SHA-256 hash — plaintext never in DB
 * - Single-use: deleted on consumption
 * - redirect_origin must match (prevents code interception)
 * - tenant_id must match (prevents cross-tenant code use)
 * - PKCE enforced for admin flows (code_challenge stored with auth code)
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { signJwt, sha256Hex } from '../crypto/jwt.js';

/**
 * Handle POST /api/token
 *
 * Accepts JSON body: { code, tenant_id, redirect_origin, code_verifier? }
 * Returns JSON: { access_token, token_type, expires_in }
 */
export async function handleTokenExchange(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Parse JSON body ──
  let code: string;
  let tenantId: string;
  let redirectOrigin: string;
  let codeVerifier: string | undefined;

  try {
    const body = await request.json() as Record<string, string>;
    code = (body.code || '').trim();
    tenantId = (body.tenant_id || '').trim();
    redirectOrigin = (body.redirect_origin || '').trim();
    codeVerifier = body.code_verifier ? body.code_verifier.trim() : undefined;
  } catch {
    return jsonError('Invalid request body', 400);
  }

  if (!code || !tenantId || !redirectOrigin) {
    return jsonError('Missing required fields: code, tenant_id, redirect_origin', 400);
  }

  // ── Hash the code and look up ──
  const codeHash = await sha256Hex(code);
  const authCodeRow = await db.consumeAuthCode(codeHash);

  if (!authCodeRow) {
    return jsonError('Invalid or expired authorization code', 400);
  }

  // ── Verify expiration ──
  const now = Math.floor(Date.now() / 1000);
  if (authCodeRow.expires_at <= now) {
    return jsonError('Authorization code has expired', 400);
  }

  // ── Verify tenant_id matches ──
  if (authCodeRow.tenant_id !== tenantId) {
    console.error(
      `Token exchange tenant mismatch: expected=${authCodeRow.tenant_id}, got=${tenantId}`
    );
    return jsonError('Authorization code tenant mismatch', 400);
  }

  // ── Verify redirect_origin matches ──
  if (authCodeRow.redirect_origin !== redirectOrigin) {
    console.error(
      `Token exchange origin mismatch: expected=${authCodeRow.redirect_origin}, got=${redirectOrigin}`
    );
    return jsonError('Authorization code origin mismatch', 400);
  }

  // ── PKCE verification (required when code_challenge is present) ──
  if (authCodeRow.code_challenge) {
    if (!codeVerifier) {
      return jsonError('PKCE code_verifier is required for this authorization code', 400);
    }
    // S256: BASE64URL(SHA256(code_verifier)) === code_challenge
    const verifierHash = await sha256Base64Url(codeVerifier);
    if (verifierHash !== authCodeRow.code_challenge) {
      return jsonError('PKCE code_verifier does not match code_challenge', 400);
    }
  }

  // ── Look up user ──
  const user = await db.getUserById(authCodeRow.user_id);
  if (!user) {
    console.error(`Token exchange: user not found: ${authCodeRow.user_id}`);
    return jsonError('User not found', 400);
  }

  // ── Sign JWT ──
  const ttlSeconds = parseInt(env.ACCESS_TOKEN_TTL_SECONDS || '900', 10);

  // Build base payload
  const jwtPayload: Record<string, unknown> = {
    sub: user.id,
    email: user.email,
    name: user.name || '',
    aud: authCodeRow.aud,
    iss: env.AUTH_DOMAIN,
  };

  // ── Admin token enrichment: add jti, roles, primaryTenantId ──
  if (authCodeRow.aud === 'admin') {
    const memberships = await db.getAdminMemberships(user.id);

    const primaryTenantId = memberships[0]?.tenant_id ?? null;
    // Scope roles to the primary tenant only (not a global flat list)
    const roles = memberships
      .filter(m => m.tenant_id === primaryTenantId)
      .map(m => m.role);

    jwtPayload.jti = crypto.randomUUID();
    jwtPayload.roles = roles;
    jwtPayload.primaryTenantId = primaryTenantId;
  }

  const accessToken = await signJwt(
    jwtPayload as Parameters<typeof signJwt>[0],
    env.JWT_PRIVATE_KEY,
    ttlSeconds
  );

  // ── Return token ──
  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ttlSeconds,
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    }
  );
}

// ─── Helpers ────────────────────────────────────────────────

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

/**
 * Compute SHA-256 of a string and return as base64url (no padding).
 * Used for PKCE S256 verification: BASE64URL(SHA256(code_verifier)).
 */
async function sha256Base64Url(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  const bytes = new Uint8Array(hashBuffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
