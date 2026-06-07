/**
 * PKCE Init Handler — server-side storage for the SPA's code_verifier.
 *
 * POST /api/pkce/init — accepts a verifier from a public SPA client, stores
 * it in the `pkce_sessions` table with a 10-minute TTL, and returns an
 * opaque `session_id`. The SPA then carries `session_id` through the OAuth
 * round-trip via URL params instead of needing to persist the verifier in
 * its own storage. At token exchange the SPA sends `pkce_session_id`, and
 * the auth Worker looks up the verifier server-side to validate PKCE.
 *
 * Why: Chrome's bounce-tracking mitigation can wipe first-party storage
 * (localStorage, sessionStorage, cookies) on cross-origin redirects for
 * domains it flags as trackers (observed on hub.centerpiecelab.com — the
 * .com TLD — but not on the .dev staging domain). URL params survive
 * cross-origin navigation by definition, so threading an opaque session_id
 * through URL params side-steps the intervention entirely.
 *
 * Security:
 * - 10-min TTL: same window as auth_codes
 * - Single-use: the session row is deleted on consumption at token exchange
 * - The verifier is stored plaintext, which is acceptable because anyone
 *   with DB access already has the auth_code rows and could issue tokens
 *   directly; storing the verifier alongside doesn't worsen the threat model
 * - No authentication required to call this endpoint: PKCE's whole point is
 *   to protect a public client. The verifier itself is a random nonce; an
 *   attacker who can call this endpoint can only burn session_ids without
 *   gaining access (the matching auth_code is still required for exchange)
 */

import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { generateUUID } from '../crypto/refreshTokens.js';
import { jsonError } from '../util/httpJson.js';

/**
 * Initial TTL for pkce_sessions rows.
 *
 * 30 minutes — this window must cover the entire gap between the SPA minting
 * the session (it does so eagerly when it first auto-redirects an unauthenticated
 * user to login) and the user actually completing authentication on the auth
 * login page. A login page left open / restored on browser launch / sitting
 * behind a Cloudflare challenge can dwell well past the old 10-min budget,
 * which expired the session before token exchange ("PKCE session has expired").
 * 30 min matches the admin SPA's idle-timeout window. The verifier is a
 * single-use nonce gated by the 60-second auth code, so a longer TTL has
 * negligible security cost.
 *
 * NOTE: the auth event itself re-anchors the expiry to a much shorter window
 * (PKCE_REANCHOR_TTL_SECONDS) — see refreshPkceSessionExpiry call sites in
 * handlers/login.ts and oauth/callback.ts. This initial TTL is the safety net
 * for the pre-auth dwell only.
 */
const PKCE_SESSION_TTL_SECONDS = 30 * 60;

/**
 * Re-anchor TTL applied at the moment of authentication.
 *
 * Once the user has actually authenticated (password submit or OAuth callback),
 * the only remaining hop is the 302 → SPA callback page → POST /api/token, which
 * takes seconds. We reset the session's expiry to now + 5 min at that point so
 * the pre-auth dwell on the login page becomes irrelevant. 5 min is generous
 * cover for that final hop while keeping the post-auth window tight.
 */
export const PKCE_REANCHOR_TTL_SECONDS = 5 * 60;

/** Minimum + maximum verifier length per RFC 7636 (PKCE). */
const VERIFIER_MIN_LENGTH = 43;
const VERIFIER_MAX_LENGTH = 128;
const VERIFIER_CHARSET = /^[A-Za-z0-9\-._~]+$/;

export async function handlePkceInit(request: Request, env: Env): Promise<Response> {
  let verifier: string;

  try {
    const body = await request.json() as { verifier?: unknown };
    if (typeof body.verifier !== 'string') {
      return jsonError('Missing or invalid verifier', 400);
    }
    verifier = body.verifier.trim();
  } catch {
    return jsonError('Invalid request body', 400);
  }

  // RFC 7636 §4.1: code_verifier MUST be 43-128 chars from the unreserved set.
  if (verifier.length < VERIFIER_MIN_LENGTH || verifier.length > VERIFIER_MAX_LENGTH) {
    return jsonError(`verifier must be ${VERIFIER_MIN_LENGTH}-${VERIFIER_MAX_LENGTH} characters`, 400);
  }
  if (!VERIFIER_CHARSET.test(verifier)) {
    return jsonError('verifier contains invalid characters', 400);
  }

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const sessionId = generateUUID();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + PKCE_SESSION_TTL_SECONDS;

  await db.insertPkceSession({
    id: sessionId,
    verifier,
    created_at: now,
    expires_at: expiresAt,
  });

  return new Response(
    JSON.stringify({ session_id: sessionId, expires_at: expiresAt }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    },
  );
}
