/**
 * OAuth Base Utilities
 *
 * Shared helpers for all OAuth 2.0 providers:
 * - State parameter generation + CSRF protection
 * - Nonce generation for OIDC providers
 * - PKCE support (code_verifier + code_challenge S256)
 * - State storage in D1 with 5-minute TTL
 *
 * All providers converge through the shared callback handler
 * after extracting the user profile.
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { validateRedirectUrl } from '../security/redirectValidator.js';

// ─── Types ──────────────────────────────────────────────────

export type OAuthProvider = 'google' | 'facebook' | 'apple' | 'microsoft';

export interface OAuthUserProfile {
  provider: OAuthProvider;
  providerAccountId: string;
  email: string;
  emailVerified: boolean;
  name: string;
  avatarUrl: string | null;
}

export interface OAuthStateData {
  tenantId: string;
  redirectUrl: string;
  codeVerifier: string;
  nonce: string | null;
  provider: OAuthProvider;
  /** Admin SPA's PKCE code_challenge — stored through the OAuth round trip. */
  clientCodeChallenge: string | null;
  clientCodeChallengeMethod: 'S256' | null;
  /** 'admin' | 'storefront' — audience from the initiating client. */
  audience: string | null;
}

// ─── State TTL ──────────────────────────────────────────────

/** OAuth state entries expire after 5 minutes. */
const STATE_TTL_SECONDS = 300;

// ─── Random Generation ──────────────────────────────────────

/**
 * Generate a cryptographically random hex string.
 *
 * @param byteLength - Number of random bytes (default 32 = 256 bits)
 * @returns Hex-encoded random string
 */
export function generateRandomHex(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate a cryptographically random URL-safe string for PKCE.
 *
 * @param byteLength - Number of random bytes (default 32)
 * @returns URL-safe base64-encoded string
 */
export function generateCodeVerifier(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeBytes(bytes);
}

// ─── PKCE ───────────────────────────────────────────────────

/**
 * Generate a PKCE code_challenge from a code_verifier using S256 method.
 *
 * code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
 *
 * @param codeVerifier - The code_verifier string
 * @returns Base64url-encoded SHA-256 hash
 */
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoded = new TextEncoder().encode(codeVerifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return base64UrlEncodeBytes(new Uint8Array(hashBuffer));
}

// ─── State Management ───────────────────────────────────────

/**
 * Create and store an OAuth state entry for CSRF protection.
 *
 * Stores state, PKCE code_verifier, nonce, tenant info, and redirect URL
 * in D1 with a 5-minute TTL.
 *
 * @returns The state parameter value to include in the authorization URL
 */
export async function createOAuthState(
  env: Env,
  provider: OAuthProvider,
  tenantId: string,
  redirectUrl: string,
  useNonce: boolean,
  clientCodeChallenge?: string | null,
  clientCodeChallengeMethod?: 'S256' | null,
  audience?: string | null
): Promise<{ state: string; codeVerifier: string; codeChallenge: string; nonce: string | null }> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const state = generateRandomHex(32);
  const codeVerifier = generateCodeVerifier(32);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const nonce = useNonce ? generateRandomHex(32) : null;
  const expiresAt = Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS;

  await db.insertOAuthState({
    state,
    tenant_id: tenantId,
    redirect_url: redirectUrl,
    code_verifier: codeVerifier,
    nonce,
    provider,
    expires_at: expiresAt,
    client_code_challenge: clientCodeChallenge ?? null,
    client_code_challenge_method: clientCodeChallengeMethod ?? null,
    audience: audience ?? null,
  });

  return { state, codeVerifier, codeChallenge, nonce };
}

/**
 * Consume and validate an OAuth state entry.
 *
 * Removes the state from D1 (single-use) and validates expiration.
 *
 * @returns The stored state data, or null if invalid/expired
 */
export async function consumeOAuthState(
  env: Env,
  stateValue: string
): Promise<OAuthStateData | null> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const row = await db.consumeOAuthState(stateValue);
  if (!row) return null;

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at < now) return null;

  return {
    tenantId: row.tenant_id,
    redirectUrl: row.redirect_url,
    codeVerifier: row.code_verifier,
    nonce: row.nonce,
    provider: row.provider as OAuthProvider,
    clientCodeChallenge: row.client_code_challenge ?? null,
    clientCodeChallengeMethod: row.client_code_challenge_method ?? null,
    audience: row.audience ?? null,
  };
}

// ─── Request Validation ─────────────────────────────────────

/**
 * Validate the tenant and redirect parameters from an OAuth initiation request.
 *
 * @returns Validated tenant ID and redirect URL, or an error Response
 */
export async function validateOAuthInitiation(
  request: Request,
  env: Env
): Promise<{ tenantId: string; redirectUrl: string; clientCodeChallenge: string | null; clientCodeChallengeMethod: 'S256' | null; audience: string | null } | Response> {
  const url = new URL(request.url);
  const tenant = url.searchParams.get('tenant') || '';
  const redirect = url.searchParams.get('redirect') || '';
  const clientCodeChallenge = url.searchParams.get('code_challenge') || null;
  const clientCodeChallengeMethod = (url.searchParams.get('code_challenge_method') || null) as 'S256' | null;
  const audience = url.searchParams.get('audience') || null;

  if (!redirect) {
    return oauthErrorRedirect(env, tenant, '', 'invalid_redirect');
  }

  const validation = await validateRedirectUrl(redirect, env.TENANT_CONFIGS, env.ENVIRONMENT);
  if (!validation.valid) {
    return oauthErrorRedirect(env, tenant, '', 'invalid_redirect');
  }

  return { tenantId: validation.tenantId, redirectUrl: redirect, clientCodeChallenge, clientCodeChallengeMethod, audience };
}

// ─── Error Helpers ──────────────────────────────────────────

/**
 * Redirect to the login page with an OAuth error code.
 */
export function oauthErrorRedirect(
  env: Env,
  tenant: string,
  redirect: string,
  error: string
): Response {
  const params = new URLSearchParams();
  if (tenant) params.set('tenant', tenant);
  if (redirect) params.set('redirect', redirect);
  params.set('error', error);

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${env.AUTH_DOMAIN}/login?${params.toString()}`,
      'Cache-Control': 'no-store',
    },
  });
}

// ─── Base64url Helpers ──────────────────────────────────────

export function base64UrlEncodeBytes(buffer: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';
  return atob(base64);
}
