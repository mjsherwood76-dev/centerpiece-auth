/**
 * Facebook OAuth Provider
 *
 * Implements Facebook OAuth 2.0.
 *
 * Authorization URL: https://www.facebook.com/v19.0/dialog/oauth
 * Token endpoint: https://graph.facebook.com/v19.0/oauth/access_token
 * User info: https://graph.facebook.com/me?fields=id,name,email,picture
 *
 * Facebook does NOT support OIDC nonce or PKCE, but we still generate
 * PKCE and store it for consistency. We use state for CSRF protection.
 *
 * Callback: GET /oauth/facebook/callback
 */
import type { Env } from '../types.js';
import {
  createOAuthState,
  consumeOAuthState,
  validateOAuthInitiation,
  oauthErrorRedirect,
  type OAuthUserProfile,
} from './base.js';
import { handleOAuthCallback } from './callback.js';

// ─── Facebook OAuth Configuration ───────────────────────────

const FACEBOOK_AUTH_URL = 'https://www.facebook.com/v19.0/dialog/oauth';
const FACEBOOK_TOKEN_URL = 'https://graph.facebook.com/v19.0/oauth/access_token';
const FACEBOOK_USER_INFO_URL = 'https://graph.facebook.com/me';
const FACEBOOK_SCOPES = 'email,public_profile';

// ─── Initiation ─────────────────────────────────────────────

/**
 * Handle GET /oauth/facebook — redirect to Facebook's authorization page.
 */
export async function handleFacebookOAuthInit(request: Request, env: Env): Promise<Response> {
  if (!env.FACEBOOK_APP_ID || !env.FACEBOOK_APP_SECRET) {
    return oauthErrorRedirect(env, '', '', 'oauth_not_configured');
  }

  const validation = await validateOAuthInitiation(request, env);
  if (validation instanceof Response) return validation;

  const { tenantId, redirectUrl } = validation;

  // Create OAuth state (no nonce for Facebook — not OIDC)
  const { state } = await createOAuthState(
    env,
    'facebook',
    tenantId,
    redirectUrl,
    false // no nonce — Facebook is not OIDC
  );

  // Build Facebook authorization URL
  const authUrl = new URL(FACEBOOK_AUTH_URL);
  authUrl.searchParams.set('client_id', env.FACEBOOK_APP_ID);
  authUrl.searchParams.set('redirect_uri', `${env.AUTH_DOMAIN}/oauth/facebook/callback`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', FACEBOOK_SCOPES);
  authUrl.searchParams.set('state', state);

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
 * Handle GET /oauth/facebook/callback — process Facebook's OAuth callback.
 */
export async function handleFacebookOAuthCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const stateParam = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error) {
    console.error('Facebook OAuth error:', error, url.searchParams.get('error_description'));
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  if (!code || !stateParam) {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  // Validate and consume state
  const stateData = await consumeOAuthState(env, stateParam);
  if (!stateData || stateData.provider !== 'facebook') {
    return oauthErrorRedirect(env, '', '', 'oauth_failed');
  }

  // Exchange code for access token
  let accessToken: string;
  try {
    accessToken = await exchangeFacebookCode(code, env);
  } catch (err) {
    console.error('Facebook token exchange failed:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  // Fetch user profile
  let profile: OAuthUserProfile;
  try {
    profile = await fetchFacebookProfile(accessToken);
  } catch (err) {
    console.error('Facebook profile fetch failed:', err);
    return oauthErrorRedirect(env, stateData.tenantId, stateData.redirectUrl, 'oauth_failed');
  }

  return handleOAuthCallback(request, env, profile, stateData.tenantId, stateData.redirectUrl);
}

// ─── Token Exchange ─────────────────────────────────────────

/**
 * Exchange authorization code for access token at Facebook's token endpoint.
 */
async function exchangeFacebookCode(code: string, env: Env): Promise<string> {
  const params = new URLSearchParams({
    code,
    client_id: env.FACEBOOK_APP_ID!,
    client_secret: env.FACEBOOK_APP_SECRET!,
    redirect_uri: `${env.AUTH_DOMAIN}/oauth/facebook/callback`,
  });

  const response = await fetch(`${FACEBOOK_TOKEN_URL}?${params.toString()}`);

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Facebook token exchange failed (${response.status}): ${errorBody}`);
  }

  const data = (await response.json()) as { access_token: string };
  if (!data.access_token) {
    throw new Error('No access_token in Facebook response');
  }

  return data.access_token;
}

// ─── User Profile ───────────────────────────────────────────

interface FacebookUserResponse {
  id: string;
  name?: string;
  email?: string;
  picture?: {
    data?: {
      url?: string;
    };
  };
}

/**
 * Fetch user profile from Facebook's Graph API.
 *
 * Note: Facebook does not provide an `email_verified` field.
 * Facebook's policy states that all returned emails are confirmed/verified,
 * so we treat them as verified.
 */
async function fetchFacebookProfile(accessToken: string): Promise<OAuthUserProfile> {
  const url = new URL(FACEBOOK_USER_INFO_URL);
  url.searchParams.set('fields', 'id,name,email,picture');
  url.searchParams.set('access_token', accessToken);

  const response = await fetch(url.toString());

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Facebook profile fetch failed (${response.status}): ${errorBody}`);
  }

  const data = (await response.json()) as FacebookUserResponse;

  if (!data.id) {
    throw new Error('No user ID in Facebook response');
  }

  if (!data.email) {
    throw new Error('No email in Facebook response — user may not have granted email permission');
  }

  return {
    provider: 'facebook',
    providerAccountId: data.id,
    email: data.email,
    emailVerified: true, // Facebook only returns confirmed emails
    name: data.name || '',
    avatarUrl: data.picture?.data?.url || null,
  };
}
