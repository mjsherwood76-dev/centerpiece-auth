/**
 * OAuth Third-Party Authorization Endpoint (RFC 6749 Authorization Code + PKCE)
 *
 *   GET  /oauth/authorize           → validate request, render consent screen
 *   POST /oauth/authorize/decision  → process Allow / Deny, mint authorization code
 *
 * This is the seller-facing half of the delegated-agent flow: a logged-in seller
 * authorizes a registered third-party client (Phase 3.18 Session 5 registry) to
 * act on their account. The client later exchanges the minted code for tokens at
 * POST /oauth/token (oauthToken.ts).
 *
 * Security invariants (per AI_RULES §centerpiece-auth + RFC 6749):
 * - Invalid / inactive client → 400 ERROR PAGE, never a redirect (RFC 6749 §4.1.2.1:
 *   you must not redirect to an unverified redirect_uri).
 * - redirect_uri must EXACT-MATCH an entry in the client's allow-list AND pass
 *   redirectValidator. Both checks; no substring/prefix matching.
 * - Requested scope ⊆ client allowed scopes.
 * - PKCE S256 is mandatory: code_challenge present, code_challenge_method === 'S256'.
 * - Seller must have a live session (refresh-token cookie → active D1 row). No
 *   session → 302 to /login?next=<encoded authorize url>.
 * - Consent → decision continuity is carried by an HMAC-signed request token
 *   (tamper-proof) + double-submit CSRF nonce + live-session re-check.
 *
 * @module handlers/oauthAuthorize
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { findClientById } from '../db.oauthClients.js';
import { insertAuthorizationCode } from '../db.oauthAuthorizationCodes.js';
import { loadTenantBranding } from '../branding.js';
import { renderConsentScreen } from '../pages/oauthConsent.js';
import { renderAuthPage } from '../pages/renderer.js';
import { extractRefreshToken, hashRefreshToken } from '../crypto/refreshTokens.js';
import { validateRedirectUrl } from '../security/redirectValidator.js';
import {
  signConsentRequest,
  verifyConsentRequest,
  generateCsrfToken,
  constantTimeStringEqual,
  type ConsentRequestPayload,
} from '../crypto/signedRequest.js';

// Consent screen TTL — the signed request token is valid for this window.
const CONSENT_REQUEST_TTL_SECONDS = 600; // 10 minutes

const HTML_HEADERS: Record<string, string> = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

// ─── Error page ─────────────────────────────────────────────

/**
 * Render a 400 error page. Used ONLY when we cannot safely redirect to the
 * client (invalid client, unverified redirect_uri, malformed request). Once
 * redirect_uri is verified, RFC-6749 errors go back to the client as redirect
 * params instead.
 */
async function errorPage(env: Env, message: string, status = 400): Promise<Response> {
  const branding = await loadTenantBranding(null, env);
  const body = `
    <h1 class="auth-card__title">Authorization error</h1>
    <p class="auth-card__subtitle">${escapeText(message)}</p>
    <p class="auth-footer-link">If you reached this page from an app, please return to it and try again.</p>
  `;
  const html = renderAuthPage(branding, { title: 'Authorization error', body }, env.PLATFORM_DOMAIN);
  return new Response(html, { status, headers: HTML_HEADERS });
}

/** Minimal HTML-text escaper for the error page (renderer's escapeHtml is for body fragments). */
function escapeText(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── Redirect-with-error (only after redirect_uri verified) ──

function redirectWithError(redirectUri: string, error: string, state: string): Response {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  if (state) url.searchParams.set('state', state);
  return new Response(null, {
    status: 302,
    headers: { Location: url.toString(), 'Cache-Control': 'no-store' },
  });
}

function redirectWithCode(redirectUri: string, code: string, state: string): Response {
  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  return new Response(null, {
    status: 302,
    headers: { Location: url.toString(), 'Cache-Control': 'no-store' },
  });
}

// ─── Live session ───────────────────────────────────────────

/**
 * Resolve the logged-in seller's user_id from the refresh-token cookie.
 *
 * Mirrors the session model used by /api/refresh: the cp_refresh HttpOnly cookie
 * holds a refresh token whose SHA-256 hash maps to a refresh_tokens row. The
 * session is "live" only if that row exists, is not revoked, and is not expired.
 *
 * @returns user_id, or null if there is no live session.
 */
async function resolveSessionUserId(request: Request, db: AuthDB, now: number): Promise<string | null> {
  const refreshPlaintext = extractRefreshToken(request.headers.get('Cookie'));
  if (!refreshPlaintext) return null;

  const tokenHash = await hashRefreshToken(refreshPlaintext);
  const row = await db.getRefreshTokenByHash(tokenHash);
  if (!row) return null;
  if (row.revoked_at !== null) return null;
  if (row.expires_at <= now) return null;

  return row.user_id;
}

// ─── GET /oauth/authorize ───────────────────────────────────

export async function handleOauthAuthorize(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const url = new URL(request.url);
  const q = url.searchParams;

  const clientId = (q.get('client_id') || '').trim();
  const redirectUri = (q.get('redirect_uri') || '').trim();
  const responseType = (q.get('response_type') || '').trim();
  const scopeParam = (q.get('scope') || '').trim();
  const codeChallenge = (q.get('code_challenge') || '').trim();
  const codeChallengeMethod = (q.get('code_challenge_method') || '').trim();
  const state = (q.get('state') || '').trim();

  // ── Baseline required params (before we trust any redirect) ──
  if (!clientId) return errorPage(env, 'Missing required parameter: client_id.');
  if (!redirectUri) return errorPage(env, 'Missing required parameter: redirect_uri.');

  // ── Look up client; invalid / inactive → error page (NOT redirect) ──
  const client = await findClientById(env.AUTH_DB, clientId);
  if (!client) return errorPage(env, 'Unknown or unregistered client.');
  if (client.status !== 'active') return errorPage(env, 'This client is not currently active.');

  // ── redirect_uri: EXACT allow-list match (no normalisation, no prefix match) ──
  const redirectAllowed = client.redirectUris.includes(redirectUri);
  if (!redirectAllowed) {
    return errorPage(env, 'The redirect_uri does not match a registered redirect URI for this client.');
  }

  // ── redirect_uri must also pass the platform redirect validator ──
  // (defence in depth — the allow-list is operator-controlled, but we still
  // enforce scheme/host rules per AI_RULES "never skip redirect validation").
  const redirectCheck = await validateRedirectUrl(redirectUri, env.TENANT_CONFIGS, env.ENVIRONMENT);
  if (!redirectCheck.valid) {
    return errorPage(env, 'The redirect_uri failed validation.');
  }

  // From here redirect_uri is verified — RFC 6749 errors go back to the client.

  // ── response_type must be 'code' ──
  if (responseType !== 'code') {
    return redirectWithError(redirectUri, 'unsupported_response_type', state);
  }

  // ── PKCE: S256 mandatory ──
  if (!codeChallenge) {
    return redirectWithError(redirectUri, 'invalid_request', state);
  }
  if (codeChallengeMethod !== 'S256') {
    return redirectWithError(redirectUri, 'invalid_request', state);
  }

  // ── state is required (CSRF for the client side of the flow) ──
  if (!state) {
    return redirectWithError(redirectUri, 'invalid_request', state);
  }

  // ── scope required and ⊆ client allowed scopes ──
  if (!scopeParam) {
    return redirectWithError(redirectUri, 'invalid_scope', state);
  }
  const requestedScopes = scopeParam.split(/\s+/).filter(Boolean);
  const allowed = new Set(client.allowedScopes);
  const scopeSubset = requestedScopes.every((s) => allowed.has(s));
  if (!scopeSubset || requestedScopes.length === 0) {
    return redirectWithError(redirectUri, 'invalid_scope', state);
  }

  // ── Require a live seller session ──
  const now = Math.floor(Date.now() / 1000);
  const userId = await resolveSessionUserId(request, db, now);
  if (!userId) {
    // Not logged in → bounce to login with next=<this authorize url>.
    const loginUrl = new URL('/login', env.AUTH_DOMAIN);
    loginUrl.searchParams.set('next', url.toString());
    return new Response(null, {
      status: 302,
      headers: { Location: loginUrl.toString(), 'Cache-Control': 'no-store' },
    });
  }

  // ── Build signed consent request + CSRF, render consent screen ──
  const csrfToken = generateCsrfToken();
  const payload: ConsentRequestPayload = {
    clientId,
    redirectUri,
    scopes: requestedScopes,
    codeChallenge,
    state,
    uid: userId,
    csrf: csrfToken,
    exp: now + CONSENT_REQUEST_TTL_SECONDS,
  };

  if (!env.INTERNAL_SECRET) {
    // Misconfiguration — fail closed rather than render an unsigned consent form.
    return errorPage(env, 'The authorization service is temporarily unavailable.', 503);
  }
  const signedRequest = await signConsentRequest(payload, env.INTERNAL_SECRET);

  const branding = await loadTenantBranding(null, env);
  const html = renderConsentScreen({
    branding,
    platformDomain: env.PLATFORM_DOMAIN,
    clientName: client.clientName,
    scopes: requestedScopes,
    decisionUrl: `${env.AUTH_DOMAIN}/oauth/authorize/decision`,
    signedRequest,
    csrfToken,
  });

  return new Response(html, { status: 200, headers: HTML_HEADERS });
}

// ─── POST /oauth/authorize/decision ─────────────────────────

export async function handleOauthAuthorizeDecision(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  if (!env.INTERNAL_SECRET) {
    return errorPage(env, 'The authorization service is temporarily unavailable.', 503);
  }

  // ── Parse form body ──
  let form: URLSearchParams;
  try {
    form = new URLSearchParams(await request.text());
  } catch {
    return errorPage(env, 'Malformed request.');
  }

  const signedRequest = (form.get('request') || '').trim();
  const csrfFromForm = (form.get('csrf') || '').trim();
  const decision = (form.get('decision') || '').trim();

  if (!signedRequest || !csrfFromForm) {
    return errorPage(env, 'Your authorization session is invalid or has expired. Please start again.');
  }

  // ── Verify signed request (tamper-proof + not expired) ──
  const now = Math.floor(Date.now() / 1000);
  const payload = await verifyConsentRequest(signedRequest, env.INTERNAL_SECRET, now);
  if (!payload) {
    return errorPage(env, 'Your authorization session is invalid or has expired. Please start again.');
  }

  // ── Double-submit CSRF check (constant-time) ──
  if (!constantTimeStringEqual(csrfFromForm, payload.csrf)) {
    return errorPage(env, 'Your authorization session could not be verified. Please start again.', 403);
  }

  // ── Live-session re-check: same logged-in seller as at consent time ──
  const sessionUserId = await resolveSessionUserId(request, db, now);
  if (!sessionUserId || sessionUserId !== payload.uid) {
    return errorPage(env, 'Your session has changed. Please sign in again and retry.', 403);
  }

  // redirect_uri inside the signed payload was already validated on the GET path.
  const { redirectUri, state, clientId, scopes, codeChallenge, uid } = payload;

  // ── Deny ──
  if (decision !== 'allow') {
    return redirectWithError(redirectUri, 'access_denied', state);
  }

  // ── Re-verify the client is still active at decision time ──
  const client = await findClientById(env.AUTH_DB, clientId);
  if (!client || client.status !== 'active') {
    return redirectWithError(redirectUri, 'unauthorized_client', state);
  }
  // Guard against a redirect_uri that was de-registered between consent and decision.
  if (!client.redirectUris.includes(redirectUri)) {
    return errorPage(env, 'The redirect_uri is no longer registered for this client.');
  }

  // ── Mint a one-shot authorization code (32-byte hex) ──
  const codeBytes = new Uint8Array(32);
  crypto.getRandomValues(codeBytes);
  const code = Array.from(codeBytes).map((b) => b.toString(16).padStart(2, '0')).join('');

  await insertAuthorizationCode(env.AUTH_DB, {
    code,
    clientId,
    userId: uid,
    grantedScopes: scopes,
    codeChallenge,
    redirectUri,
    expiresAt: now + 5 * 60, // 5 minutes
  });

  return redirectWithCode(redirectUri, code, state);
}
