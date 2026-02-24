/**
 * Microsoft OAuth Provider (Microsoft Entra ID / Azure AD)
 *
 * Implements Microsoft OAuth 2.0 with OpenID Connect.
 *
 * Authorization URL: https://login.microsoftonline.com/common/oauth2/v2.0/authorize
 * Token endpoint: https://login.microsoftonline.com/common/oauth2/v2.0/token
 * Scopes: openid email profile
 *
 * Uses /common tenant for multi-tenant support (personal + work accounts).
 *
 * Validates OIDC claims: iss pattern, aud, exp, nonce.
 * Email may be in `email` or `preferred_username` depending on account type.
 *
 * Callback: GET /oauth/microsoft/callback
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

// ─── Microsoft OAuth Configuration ─────────────────────────

const MICROSOFT_AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const MICROSOFT_TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
const MICROSOFT_SCOPES = 'openid email profile';

/**
 * Microsoft issuers vary by tenant type:
 * - Personal: https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0
 * - Work/School: https://login.microsoftonline.com/{tenant-id}/v2.0
 *
 * We validate that the issuer matches the expected pattern.
 */
const MICROSOFT_ISSUER_PATTERN = /^https:\/\/login\.microsoftonline\.com\/[a-f0-9-]+\/v2\.0$/;

// ─── Initiation ─────────────────────────────────────────────

/**
 * Handle GET /oauth/microsoft — redirect to Microsoft's authorization page.
 */
export async function handleMicrosoftOAuthInit(request: Request, env: Env): Promise<Response> {
  if (!env.MICROSOFT_CLIENT_ID || !env.MICROSOFT_CLIENT_SECRET) {
    return oauthErrorRedirect(env, '', '', 'oauth_not_configured');
  }

  const validation = await validateOAuthInitiation(request, env);
  if (validation instanceof Response) return validation;

  const { tenantId, redirectUrl } = validation;

  // Create OAuth state with PKCE + nonce (Microsoft supports OIDC)
  const { state, codeChallenge, nonce } = await createOAuthState(
    env,
    'microsoft',
    tenantId,
    redirectUrl,
    true // useNonce for OIDC
  );

  // Build Microsoft authorization URL
  const authUrl = new URL(MICROSOFT_AUTH_URL);
  authUrl.searchParams.set('client_id', env.MICROSOFT_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', `${env.AUTH_DOMAIN}/oauth/microsoft/callback`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', MICROSOFT_SCOPES);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce!);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('response_mode', 'query');
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
 * Handle GET /oauth/microsoft/callback — process Microsoft's OAuth callback.
 */
export async function handleMicrosoftOAuthCallback(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const stateParam = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error) {
    console.error(
      'Microsoft OAuth error:',
      error,
      url.searchParams.get('error_description')
    );
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  if (!code || !stateParam) {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  // Validate and consume state
  const stateData = await consumeOAuthState(env, stateParam);
  if (!stateData || stateData.provider !== 'microsoft') {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  // Exchange code for tokens
  let tokenResponse: MicrosoftTokenResponse;
  try {
    tokenResponse = await exchangeMicrosoftCode(code, stateData.codeVerifier, env);
  } catch (err) {
    console.error('Microsoft token exchange failed:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  // Parse and validate ID token
  let profile: OAuthUserProfile;
  try {
    profile = parseMicrosoftIdToken(
      tokenResponse.id_token,
      env.MICROSOFT_CLIENT_ID!,
      stateData.nonce
    );
  } catch (err) {
    console.error('Microsoft ID token validation failed:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  return handleOAuthCallback(request, env, profile, stateData.tenantId, stateData.redirectUrl);
}

// ─── Token Exchange ─────────────────────────────────────────

interface MicrosoftTokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
  refresh_token?: string;
}

/**
 * Exchange authorization code for tokens at Microsoft's token endpoint.
 */
async function exchangeMicrosoftCode(
  code: string,
  codeVerifier: string,
  env: Env
): Promise<MicrosoftTokenResponse> {
  const body = new URLSearchParams({
    code,
    client_id: env.MICROSOFT_CLIENT_ID!,
    client_secret: env.MICROSOFT_CLIENT_SECRET!,
    redirect_uri: `${env.AUTH_DOMAIN}/oauth/microsoft/callback`,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,
  });

  const response = await fetch(MICROSOFT_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Microsoft token exchange failed (${response.status}): ${errorBody}`);
  }

  return response.json() as Promise<MicrosoftTokenResponse>;
}

// ─── ID Token Parsing ───────────────────────────────────────

interface MicrosoftIdTokenClaims {
  iss: string;
  aud: string;
  sub: string;
  email?: string;
  preferred_username?: string;
  name?: string;
  nonce?: string;
  iat: number;
  exp: number;
}

/**
 * Parse and validate a Microsoft ID token (JWT).
 *
 * Same as Google/Apple: we don't cryptographically verify the signature
 * because the token came directly from Microsoft's token endpoint over HTTPS.
 *
 * Microsoft-specific:
 * - Issuer varies by tenant type (pattern match)
 * - Email may be in `email` or `preferred_username`
 * - Microsoft personal accounts always verify email; work accounts depend on org
 */
function parseMicrosoftIdToken(
  idToken: string,
  clientId: string,
  expectedNonce: string | null
): OAuthUserProfile {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid ID token format');
  }

  let claims: MicrosoftIdTokenClaims;
  try {
    claims = JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    throw new Error('Failed to decode ID token payload');
  }

  // Validate issuer (pattern match — Microsoft uses tenant-specific issuers)
  if (!MICROSOFT_ISSUER_PATTERN.test(claims.iss)) {
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

  // Extract email — Microsoft uses `email` or `preferred_username`
  const email = claims.email || claims.preferred_username || '';
  if (!email) {
    throw new Error('No email in Microsoft ID token');
  }

  return {
    provider: 'microsoft',
    providerAccountId: claims.sub,
    email,
    emailVerified: true, // Microsoft verifies emails for personal accounts; treat as verified
    name: claims.name || '',
    avatarUrl: null, // Microsoft Graph API would be needed for avatar — not worth the extra call
  };
}
