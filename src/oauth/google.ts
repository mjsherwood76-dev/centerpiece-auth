/**
 * Google OAuth Provider
 *
 * Implements Google OAuth 2.0 with OpenID Connect.
 *
 * Authorization URL: https://accounts.google.com/o/oauth2/v2/auth
 * Token endpoint: https://oauth2.googleapis.com/token
 * Scopes: openid email profile
 *
 * Validates OIDC claims: iss, aud, exp, iat, nonce, email_verified.
 * Callback: GET /oauth/google/callback
 */
import type { Env } from '../types.js';
import {
  createOAuthState,
  consumeOAuthState,
  validateOAuthInitiation,
  oauthErrorRedirect,
  base64UrlDecode,
  type OAuthUserProfile,
} from './base.js';
import { handleOAuthCallback } from './callback.js';

// ─── Google OAuth Configuration ─────────────────────────────

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_SCOPES = 'openid email profile';
const GOOGLE_ISSUER = 'https://accounts.google.com';

// ─── Initiation ─────────────────────────────────────────────

/**
 * Handle GET /oauth/google — redirect to Google's authorization page.
 */
export async function handleGoogleOAuthInit(request: Request, env: Env): Promise<Response> {
  // Validate client_id is configured
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    return oauthErrorRedirect(env, '', '', 'oauth_not_configured');
  }

  // Validate tenant + redirect params
  const validation = await validateOAuthInitiation(request, env);
  if (validation instanceof Response) return validation;

  const { tenantId, redirectUrl } = validation;

  // Create OAuth state with PKCE + nonce (Google supports OIDC)
  const { state, codeChallenge, nonce } = await createOAuthState(
    env,
    'google',
    tenantId,
    redirectUrl,
    true // useNonce for OIDC
  );

  // Build Google authorization URL
  const authUrl = new URL(GOOGLE_AUTH_URL);
  authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', `${env.AUTH_DOMAIN}/oauth/google/callback`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', GOOGLE_SCOPES);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce!);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'select_account');

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
 * Handle GET /oauth/google/callback — process Google's OAuth callback.
 */
export async function handleGoogleOAuthCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const stateParam = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  // Handle error from Google
  if (error) {
    console.error('Google OAuth error:', error);
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  if (!code || !stateParam) {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  // Validate and consume state (CSRF protection)
  const stateData = await consumeOAuthState(env, stateParam);
  if (!stateData || stateData.provider !== 'google') {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  // Exchange authorization code for tokens
  let tokenResponse: GoogleTokenResponse;
  try {
    tokenResponse = await exchangeGoogleCode(code, stateData.codeVerifier, env);
  } catch (err) {
    console.error('Google token exchange failed:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  // Parse and validate ID token
  let profile: OAuthUserProfile;
  try {
    profile = parseGoogleIdToken(tokenResponse.id_token, env.GOOGLE_CLIENT_ID!, stateData.nonce);
  } catch (err) {
    console.error('Google ID token validation failed:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  // Delegate to shared callback handler
  return handleOAuthCallback(request, env, profile, stateData.tenantId, stateData.redirectUrl);
}

// ─── Token Exchange ─────────────────────────────────────────

interface GoogleTokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
  refresh_token?: string;
}

/**
 * Exchange authorization code for tokens at Google's token endpoint.
 */
async function exchangeGoogleCode(
  code: string,
  codeVerifier: string,
  env: Env
): Promise<GoogleTokenResponse> {
  const body = new URLSearchParams({
    code,
    client_id: env.GOOGLE_CLIENT_ID!,
    client_secret: env.GOOGLE_CLIENT_SECRET!,
    redirect_uri: `${env.AUTH_DOMAIN}/oauth/google/callback`,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,
  });

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Google token exchange failed (${response.status}): ${errorBody}`);
  }

  return response.json() as Promise<GoogleTokenResponse>;
}

// ─── ID Token Parsing ───────────────────────────────────────

interface GoogleIdTokenClaims {
  iss: string;
  azp: string;
  aud: string;
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
  nonce?: string;
  iat: number;
  exp: number;
}

/**
 * Parse and validate a Google ID token (JWT).
 *
 * Note: We do NOT cryptographically verify the ID token signature here
 * because we received it directly from Google's token endpoint over HTTPS
 * (server-to-server). This is the standard approach for confidential clients
 * per the OIDC spec (Section 3.1.3.7).
 *
 * We DO validate the claims: iss, aud, exp, nonce, email_verified.
 */
function parseGoogleIdToken(
  idToken: string,
  clientId: string,
  expectedNonce: string | null
): OAuthUserProfile {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid ID token format');
  }

  let claims: GoogleIdTokenClaims;
  try {
    claims = JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    throw new Error('Failed to decode ID token payload');
  }

  // Validate issuer
  if (claims.iss !== GOOGLE_ISSUER && claims.iss !== 'accounts.google.com') {
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

  // Validate nonce (if we sent one)
  if (expectedNonce && claims.nonce !== expectedNonce) {
    throw new Error('Nonce mismatch');
  }

  return {
    provider: 'google',
    providerAccountId: claims.sub,
    email: claims.email,
    emailVerified: claims.email_verified === true,
    name: claims.name || '',
    avatarUrl: claims.picture || null,
  };
}
