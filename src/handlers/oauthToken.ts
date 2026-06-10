/**
 * OAuth Third-Party Token Endpoint (RFC 6749 §3.2, §4.1.3, §6)
 *
 *   POST /oauth/token
 *
 * The client-facing half of the delegated-agent flow. A registered third-party
 * client exchanges an authorization code (minted by /oauth/authorize/decision)
 * for an access token + refresh token, or rotates a refresh token for a fresh
 * access token.
 *
 * Client authentication (RFC 6749 §2.3.1):
 *   - `Authorization: Basic base64(client_id:client_secret)`  (client_secret_basic)
 *   - OR body params `client_id` + `client_secret`            (client_secret_post)
 *
 * Grants:
 *   - grant_type=authorization_code: validates the code (exists / not expired /
 *     not used — one-shot), validates PKCE (S256: BASE64URL(SHA256(verifier)) ===
 *     stored code_challenge), validates redirect_uri match, validates the code
 *     belongs to the authenticating client, marks the code used, issues tokens.
 *   - grant_type=refresh_token: rotates the refresh token via the existing
 *     family-based rotation + theft-detection path, issues a fresh access token.
 *
 * Access tokens carry an `act_as: { client_id }` claim so downstream resource
 * servers can distinguish delegated-agent traffic from direct seller traffic.
 *
 * Token security (AI_RULES §centerpiece-auth):
 * - Authorization codes are single-use; replay → 400 (one-shot via used_at).
 * - Refresh tokens are stored SHA-256-hashed; never in plaintext.
 * - Client secrets verified via constant-time PBKDF2 comparison.
 * - PKCE comparison uses the existing SHA-256 base64url helper.
 *
 * @module handlers/oauthToken
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { findClientById, verifyClientSecret } from '../db.oauthClients.js';
import { consumeAuthorizationCode } from '../db.oauthAuthorizationCodes.js';
import {
  signJwt,
  sha256Base64Url,
  buildCustomerJwtPayload,
  type UnsignedJwtClaims,
} from '../crypto/jwt.js';
import {
  generateRefreshToken,
  hashRefreshToken,
  generateUUID,
} from '../crypto/refreshTokens.js';
import { constantTimeStringEqual } from '../crypto/signedRequest.js';

// RFC 6749 error responses are JSON with no-store caching.
function tokenError(error: string, description: string, status = 400): Response {
  return new Response(JSON.stringify({ error, error_description: description }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', Pragma: 'no-cache' },
  });
}

// ─── Client authentication ──────────────────────────────────

interface ClientCredentials {
  clientId: string;
  clientSecret: string;
}

/**
 * Extract client credentials from the request — Basic header takes precedence,
 * then body params. Returns null if neither is present/parseable.
 */
function extractClientCredentials(
  request: Request,
  form: URLSearchParams,
): ClientCredentials | null {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const decoded = atob(authHeader.slice(6).trim());
      const sep = decoded.indexOf(':');
      if (sep > 0) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, sep)),
          clientSecret: decodeURIComponent(decoded.slice(sep + 1)),
        };
      }
    } catch {
      return null;
    }
    return null;
  }

  const clientId = (form.get('client_id') || '').trim();
  const clientSecret = form.get('client_secret') || '';
  if (clientId && clientSecret) {
    return { clientId, clientSecret };
  }
  return null;
}

// ─── Handler ────────────────────────────────────────────────

export async function handleOauthToken(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Parse form body (RFC 6749 uses application/x-www-form-urlencoded) ──
  let form: URLSearchParams;
  try {
    form = new URLSearchParams(await request.text());
  } catch {
    return tokenError('invalid_request', 'Malformed request body.');
  }

  // ── Authenticate the client ──
  const creds = extractClientCredentials(request, form);
  if (!creds) {
    return tokenError('invalid_client', 'Client authentication required.', 401);
  }

  const client = await findClientById(env.AUTH_DB, creds.clientId);
  if (!client || client.status !== 'active') {
    return tokenError('invalid_client', 'Unknown or inactive client.', 401);
  }

  const secretOk = await verifyClientSecret(env.AUTH_DB, creds.clientId, creds.clientSecret);
  if (!secretOk) {
    return tokenError('invalid_client', 'Client authentication failed.', 401);
  }

  const grantType = (form.get('grant_type') || '').trim();

  if (grantType === 'authorization_code') {
    return handleAuthorizationCodeGrant(form, env, db, client.clientId);
  }
  if (grantType === 'refresh_token') {
    return handleRefreshTokenGrant(form, env, db, client.clientId);
  }
  return tokenError('unsupported_grant_type', `Unsupported grant_type: ${grantType || '(none)'}.`);
}

// ─── authorization_code grant ───────────────────────────────

async function handleAuthorizationCodeGrant(
  form: URLSearchParams,
  env: Env,
  db: AuthDB,
  authenticatedClientId: string,
): Promise<Response> {
  const code = (form.get('code') || '').trim();
  const redirectUri = (form.get('redirect_uri') || '').trim();
  const codeVerifier = (form.get('code_verifier') || '').trim();

  if (!code) return tokenError('invalid_request', 'Missing code.');
  if (!redirectUri) return tokenError('invalid_request', 'Missing redirect_uri.');
  if (!codeVerifier) return tokenError('invalid_request', 'Missing code_verifier (PKCE required).');

  const now = Math.floor(Date.now() / 1000);

  // One-shot consume: handles not_found / already_used (replay) / expired.
  const result = await consumeAuthorizationCode(env.AUTH_DB, code, now);
  if (!result.ok) {
    // All failure reasons collapse to invalid_grant per RFC 6749 §5.2.
    return tokenError('invalid_grant', 'Authorization code is invalid, expired, or already used.');
  }
  const authCode = result.code;

  // ── Code must belong to the authenticating client ──
  if (authCode.clientId !== authenticatedClientId) {
    return tokenError('invalid_grant', 'Authorization code was not issued to this client.');
  }

  // ── redirect_uri must match the one the code was bound to ──
  if (authCode.redirectUri !== redirectUri) {
    return tokenError('invalid_grant', 'redirect_uri does not match the authorization request.');
  }

  // ── PKCE S256 verification ──
  // BASE64URL(SHA256(code_verifier)) must equal the stored code_challenge.
  const verifierHash = await sha256Base64Url(codeVerifier);
  if (!constantTimeStringEqual(verifierHash, authCode.codeChallenge)) {
    return tokenError('invalid_grant', 'PKCE verification failed.');
  }

  // ── Look up the user ──
  const user = await db.getUserById(authCode.userId);
  if (!user) {
    return tokenError('invalid_grant', 'The authorizing user no longer exists.');
  }

  return issueTokens(env, db, {
    user,
    clientId: authenticatedClientId,
    scopes: authCode.grantedScopes,
  });
}

// ─── refresh_token grant ────────────────────────────────────

async function handleRefreshTokenGrant(
  form: URLSearchParams,
  env: Env,
  db: AuthDB,
  authenticatedClientId: string,
): Promise<Response> {
  const refreshTokenPlaintext = (form.get('refresh_token') || '').trim();
  const scopeParam = (form.get('scope') || '').trim();
  if (!refreshTokenPlaintext) {
    return tokenError('invalid_request', 'Missing refresh_token.');
  }

  const now = Math.floor(Date.now() / 1000);
  const tokenHash = await hashRefreshToken(refreshTokenPlaintext);
  const existing = await db.getRefreshTokenByHash(tokenHash);

  if (!existing) {
    return tokenError('invalid_grant', 'Refresh token is invalid.');
  }

  // ── Client binding (review C2) ──
  // The token must have been issued to the authenticating client via this
  // endpoint. First-party session tokens (login/register/cookie-refresh flows)
  // have client_id NULL and can NEVER be rotated through the third-party
  // grant. Checked before any state change; the error is indistinguishable
  // from an unknown token so clients can't probe other clients' tokens.
  if (existing.client_id === null || existing.client_id !== authenticatedClientId) {
    return tokenError('invalid_grant', 'Refresh token is invalid.');
  }

  // Reuse / theft detection: a presented-but-revoked token revokes the family.
  if (existing.revoked_at !== null) {
    await db.revokeRefreshTokenFamily(existing.family_id);
    return tokenError('invalid_grant', 'Refresh token has been revoked.');
  }

  if (existing.expires_at <= now) {
    return tokenError('invalid_grant', 'Refresh token has expired.');
  }

  // ── Scope enforcement (review M3, RFC 6749 §6) ──
  // The refreshed grant is limited to the scopes granted at issuance. A
  // requested scope may only narrow, never broaden. Checked before rotation
  // so an invalid_scope request doesn't burn the presented token.
  const grantedScopes = (existing.granted_scopes ?? '').split(/\s+/).filter(Boolean);
  let scopes = grantedScopes;
  if (scopeParam) {
    const requested = scopeParam.split(/\s+/).filter(Boolean);
    if (requested.some((s) => !grantedScopes.includes(s))) {
      return tokenError('invalid_scope', 'Requested scope exceeds the originally granted scope.');
    }
    scopes = requested;
  }

  // Rotate: revoke old, issue new in the same family (existing helper handles
  // the theft-detection race).
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const newRefreshToken = generateRefreshToken();
  const newRefreshTokenHash = await hashRefreshToken(newRefreshToken);
  const newExpiresAt = now + refreshTtlDays * 24 * 60 * 60;
  const newTokenId = generateUUID();

  const rotation = await db.rotateRefreshToken(tokenHash, {
    id: newTokenId,
    user_id: existing.user_id,
    token_hash: newRefreshTokenHash,
    family_id: existing.family_id,
    expires_at: newExpiresAt,
  });
  if (!rotation.success) {
    return tokenError('invalid_grant', 'Refresh token could not be rotated.');
  }

  const user = await db.getUserById(existing.user_id);
  if (!user) {
    return tokenError('invalid_grant', 'The authorizing user no longer exists.');
  }

  return issueTokens(env, db, {
    user,
    clientId: authenticatedClientId,
    scopes,
    existingRefreshToken: newRefreshToken,
  });
}

// ─── Shared token issuance ──────────────────────────────────

async function issueTokens(
  env: Env,
  db: AuthDB,
  params: {
    user: { id: string; email: string; name: string | null; email_verified: number };
    clientId: string;
    scopes: string[];
    /** When set (refresh grant), reuse the already-rotated refresh token instead of minting a family. */
    existingRefreshToken?: string;
  },
): Promise<Response> {
  const ttlSeconds = parseInt(env.ACCESS_TOKEN_TTL_SECONDS || '900', 10);
  const now = Math.floor(Date.now() / 1000);

  // ── Access token (storefront audience + act_as delegated-agent claim) ──
  const base = buildCustomerJwtPayload({
    userId: params.user.id,
    email: params.user.email,
    name: params.user.name || '',
    iss: env.AUTH_DOMAIN,
    // Reflect the persisted verification state. For OAuth-linked accounts this
    // was set true at link time only when the provider confirmed the email
    // (repo AI_RULES OAuth-linking rule). Keeps the platform-wide claim correct;
    // Valhallan itself uses the email/PIN path, not customer OAuth.
    emailVerified: params.user.email_verified === 1,
  });
  // TODO(5.7): platform-api ignores `act_as` until Phase 5.7 wires per-agent
  // RBAC. Until then a delegated-agent token has the same authority as a direct
  // seller token — acceptable because no third-party client is live in prod yet.
  const unsigned: UnsignedJwtClaims = { ...base, act_as: { client_id: params.clientId } };
  const accessToken = await signJwt(unsigned, env.JWT_PRIVATE_KEY, ttlSeconds);

  // ── Refresh token ──
  let refreshToken: string;
  if (params.existingRefreshToken) {
    refreshToken = params.existingRefreshToken;
  } else {
    // Mint a brand-new refresh-token family for this delegated grant, bound
    // to the issuing client with its granted scopes (migration 0013) so the
    // refresh grant can enforce both (review C2/M3).
    const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
    refreshToken = generateRefreshToken();
    const refreshTokenHash = await hashRefreshToken(refreshToken);
    const familyId = generateUUID();
    const tokenId = generateUUID();
    await db.insertRefreshToken({
      id: tokenId,
      user_id: params.user.id,
      token_hash: refreshTokenHash,
      family_id: familyId,
      expires_at: now + refreshTtlDays * 24 * 60 * 60,
      login_iat: now,
      client_id: params.clientId,
      granted_scopes: params.scopes.length > 0 ? params.scopes.join(' ') : null,
    });
  }

  const responseBody = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ttlSeconds,
    refresh_token: refreshToken,
    scope: params.scopes.join(' '),
  };

  return new Response(JSON.stringify(responseBody), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', Pragma: 'no-cache' },
  });
}
