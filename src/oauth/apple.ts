/**
 * Apple OAuth Provider (Sign in with Apple)
 *
 * Implements Apple's OAuth 2.0 / OpenID Connect flow.
 *
 * Authorization URL: https://appleid.apple.com/auth/authorize
 * Token endpoint: https://appleid.apple.com/auth/token
 *
 * Key differences from other providers:
 * - Callback uses POST (form_post response mode), not GET
 * - Requires a client secret JWT signed with Apple's ES256 private key
 * - Name is only provided on the FIRST login — must store immediately
 * - Email is always verified by Apple
 *
 * Callback: POST /oauth/apple/callback
 */
import type { Env } from '../types.js';
import {
  createOAuthState,
  consumeOAuthState,
  validateOAuthInitiation,
  oauthErrorRedirect,
  base64UrlDecode,
  base64UrlEncodeBytes,
  base64UrlEncode,
  type OAuthUserProfile,
} from './base.js';
import { handleOAuthCallback } from './callback.js';

// ─── Apple OAuth Configuration ──────────────────────────────

const APPLE_AUTH_URL = 'https://appleid.apple.com/auth/authorize';
const APPLE_TOKEN_URL = 'https://appleid.apple.com/auth/token';
const APPLE_SCOPES = 'openid email name';
const APPLE_ISSUER = 'https://appleid.apple.com';

/** Apple client secret JWTs are valid for up to 6 months (we use 5 min). */
const APPLE_SECRET_TTL_SECONDS = 300;

// ─── Initiation ─────────────────────────────────────────────

/**
 * Handle GET /oauth/apple — redirect to Apple's authorization page.
 */
export async function handleAppleOAuthInit(request: Request, env: Env): Promise<Response> {
  if (!env.APPLE_CLIENT_ID || !env.APPLE_PRIVATE_KEY || !env.APPLE_KEY_ID || !env.APPLE_TEAM_ID) {
    return oauthErrorRedirect(env, '', '', 'oauth_not_configured');
  }

  const validation = await validateOAuthInitiation(request, env);
  if (validation instanceof Response) return validation;

  const { tenantId, redirectUrl } = validation;

  // Create OAuth state with nonce (Apple supports OIDC)
  const { state, nonce } = await createOAuthState(
    env,
    'apple',
    tenantId,
    redirectUrl,
    true // useNonce for OIDC
  );

  // Build Apple authorization URL
  const authUrl = new URL(APPLE_AUTH_URL);
  authUrl.searchParams.set('client_id', env.APPLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', `${env.AUTH_DOMAIN}/oauth/apple/callback`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', APPLE_SCOPES);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce!);
  authUrl.searchParams.set('response_mode', 'form_post'); // Apple uses form POST

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      'Cache-Control': 'no-store',
    },
  });
}

// ─── Callback ───────────────────────────────────────────────

/**
 * Handle POST /oauth/apple/callback — process Apple's OAuth callback.
 *
 * Apple uses form_post response mode, so the callback is a POST with
 * form-encoded body containing: code, state, id_token, and optionally user.
 */
export async function handleAppleOAuthCallback(request: Request, env: Env): Promise<Response> {
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  const code = formData.get('code') as string | null;
  const stateParam = formData.get('state') as string | null;
  const error = formData.get('error') as string | null;
  const userJson = formData.get('user') as string | null; // Only on first login

  if (error) {
    console.error('Apple OAuth error:', error);
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  if (!code || !stateParam) {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  // Validate and consume state
  const stateData = await consumeOAuthState(env, stateParam);
  if (!stateData || stateData.provider !== 'apple') {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  // Parse user info from first login (Apple only sends this once)
  let firstName = '';
  let lastName = '';
  if (userJson) {
    try {
      const userData = JSON.parse(userJson) as {
        name?: { firstName?: string; lastName?: string };
        email?: string;
      };
      firstName = userData.name?.firstName || '';
      lastName = userData.name?.lastName || '';
    } catch {
      // Non-critical — name is optional
    }
  }

  // Generate Apple client secret JWT
  let clientSecret: string;
  try {
    clientSecret = await generateAppleClientSecret(env);
  } catch (err) {
    console.error('Failed to generate Apple client secret:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  // Exchange code for tokens
  let tokenResponse: AppleTokenResponse;
  try {
    tokenResponse = await exchangeAppleCode(code, clientSecret, env);
  } catch (err) {
    console.error('Apple token exchange failed:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  // Parse and validate ID token
  let profile: OAuthUserProfile;
  try {
    profile = parseAppleIdToken(
      tokenResponse.id_token,
      env.APPLE_CLIENT_ID!,
      stateData.nonce,
      firstName,
      lastName
    );
  } catch (err) {
    console.error('Apple ID token validation failed:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  return handleOAuthCallback(request, env, profile, stateData.tenantId, stateData.redirectUrl);
}

// ─── Apple Client Secret JWT ────────────────────────────────

/**
 * Generate a client secret JWT for Apple Sign In.
 *
 * Apple requires the client_secret to be a JWT signed with the app's
 * ES256 private key (not the same as our JWT signing key).
 *
 * Header: { alg: "ES256", kid: APPLE_KEY_ID }
 * Payload: { iss: APPLE_TEAM_ID, iat, exp, aud: "https://appleid.apple.com", sub: APPLE_CLIENT_ID }
 */
async function generateAppleClientSecret(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: 'ES256',
    kid: env.APPLE_KEY_ID!,
  };

  const payload = {
    iss: env.APPLE_TEAM_ID!,
    iat: now,
    exp: now + APPLE_SECRET_TTL_SECONDS,
    aud: APPLE_ISSUER,
    sub: env.APPLE_CLIENT_ID!,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // Import Apple's ES256 private key
  const privateKey = await importApplePrivateKey(env.APPLE_PRIVATE_KEY!);

  // Sign
  const signatureBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(signingInput)
  );

  const encodedSignature = base64UrlEncodeBytes(new Uint8Array(signatureBuffer));

  return `${signingInput}.${encodedSignature}`;
}

/**
 * Import Apple's base64-encoded PEM private key for ES256 signing.
 */
async function importApplePrivateKey(base64Pem: string): Promise<CryptoKey> {
  const pem = atob(base64Pem);
  const header = '-----BEGIN PRIVATE KEY-----';
  const footer = '-----END PRIVATE KEY-----';
  const keyBase64 = pem.replace(header, '').replace(footer, '').replace(/\s/g, '');
  const keyBinary = atob(keyBase64);
  const keyBytes = new Uint8Array(keyBinary.length);
  for (let i = 0; i < keyBinary.length; i++) {
    keyBytes[i] = keyBinary.charCodeAt(i);
  }

  return crypto.subtle.importKey(
    'pkcs8',
    keyBytes.buffer as ArrayBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
}

// ─── Token Exchange ─────────────────────────────────────────

interface AppleTokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
}

/**
 * Exchange authorization code for tokens at Apple's token endpoint.
 */
async function exchangeAppleCode(
  code: string,
  clientSecret: string,
  env: Env
): Promise<AppleTokenResponse> {
  const body = new URLSearchParams({
    code,
    client_id: env.APPLE_CLIENT_ID!,
    client_secret: clientSecret,
    redirect_uri: `${env.AUTH_DOMAIN}/oauth/apple/callback`,
    grant_type: 'authorization_code',
  });

  const response = await fetch(APPLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Apple token exchange failed (${response.status}): ${errorBody}`);
  }

  return response.json() as Promise<AppleTokenResponse>;
}

// ─── ID Token Parsing ───────────────────────────────────────

interface AppleIdTokenClaims {
  iss: string;
  aud: string;
  sub: string;
  email?: string;
  email_verified?: string | boolean; // Apple sends "true" as a string
  nonce?: string;
  iat: number;
  exp: number;
  is_private_email?: string | boolean;
}

/**
 * Parse and validate an Apple ID token (JWT).
 *
 * Same as Google: we don't cryptographically verify the signature because
 * the token came directly from Apple's token endpoint over HTTPS.
 *
 * Apple-specific:
 * - email is always verified by Apple
 * - name is only provided on FIRST login (passed in separately)
 * - email_verified may be a string "true" not boolean
 */
function parseAppleIdToken(
  idToken: string,
  clientId: string,
  expectedNonce: string | null,
  firstName: string,
  lastName: string
): OAuthUserProfile {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid ID token format');
  }

  let claims: AppleIdTokenClaims;
  try {
    claims = JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    throw new Error('Failed to decode ID token payload');
  }

  // Validate issuer
  if (claims.iss !== APPLE_ISSUER) {
    throw new Error(`Invalid issuer: ${claims.iss}`);
  }

  // Validate audience
  if (claims.aud !== clientId) {
    throw new Error(`Invalid audience: ${claims.aud}`);
  }

  // Validate expiration
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp <= now) {
    throw new Error('ID token expired');
  }

  // Validate nonce
  if (expectedNonce && claims.nonce !== expectedNonce) {
    throw new Error('Nonce mismatch');
  }

  // Build name from first login data (Apple only sends it once)
  const name = [firstName, lastName].filter(Boolean).join(' ');

  return {
    provider: 'apple',
    providerAccountId: claims.sub,
    email: claims.email || '',
    emailVerified: true, // Apple always verifies emails
    name,
    avatarUrl: null, // Apple does not provide avatars
  };
}
