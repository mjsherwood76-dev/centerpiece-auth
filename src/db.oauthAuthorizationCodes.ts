/**
 * OAuth Third-Party Authorization Codes — D1 helpers
 *
 * CRUD for the `oauth_authorization_codes` table (migration 0010). Backs the
 * third-party Authorization Code + PKCE flow:
 *   GET  /oauth/authorize          → consent screen
 *   POST /oauth/authorize/decision → Allow mints a code into this table
 *   POST /oauth/token              → exchanges the code for tokens (one-shot)
 *
 * Security model:
 * - The `code` column IS the secret: a 32-byte random hex value used as the PK.
 *   This is the plan's design (Phase 3.18 Session 6) — the code is high-entropy,
 *   single-use, and short-lived (5 min), and is never returned to the browser
 *   except as a one-time redirect param to the verified client redirect_uri.
 * - One-shot enforcement: `consumeAuthorizationCode` atomically stamps `used_at`
 *   via a conditional UPDATE (WHERE used_at IS NULL). A second exchange of the
 *   same code finds `used_at` already set and is rejected (replay → 400).
 *
 * @module db.oauthAuthorizationCodes
 */

// ─── Types ──────────────────────────────────────────────────

export interface OAuthAuthorizationCodeRow {
  code: string;
  client_id: string;
  user_id: string;
  granted_scopes_json: string;
  code_challenge: string;
  redirect_uri: string;
  expires_at: number;
  used_at: number | null;
}

export interface OAuthAuthorizationCode {
  code: string;
  clientId: string;
  userId: string;
  grantedScopes: string[];
  codeChallenge: string;
  redirectUri: string;
  expiresAt: number;
  usedAt: number | null;
}

function rowToCode(row: OAuthAuthorizationCodeRow): OAuthAuthorizationCode {
  return {
    code: row.code,
    clientId: row.client_id,
    userId: row.user_id,
    grantedScopes: JSON.parse(row.granted_scopes_json) as string[],
    codeChallenge: row.code_challenge,
    redirectUri: row.redirect_uri,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
  };
}

// ─── Insert ─────────────────────────────────────────────────

/**
 * Insert a freshly-minted authorization code.
 *
 * Caller supplies the random `code` (32-byte hex). `used_at` starts NULL.
 */
export async function insertAuthorizationCode(
  db: D1Database,
  params: {
    code: string;
    clientId: string;
    userId: string;
    grantedScopes: string[];
    codeChallenge: string;
    redirectUri: string;
    expiresAt: number;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO oauth_authorization_codes
         (code, client_id, user_id, granted_scopes_json, code_challenge, redirect_uri, expires_at, used_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
    )
    .bind(
      params.code,
      params.clientId,
      params.userId,
      JSON.stringify(params.grantedScopes),
      params.codeChallenge,
      params.redirectUri,
      params.expiresAt,
    )
    .run();
}

// ─── Consume (one-shot) ─────────────────────────────────────

export type ConsumeAuthorizationCodeResult =
  | { ok: true; code: OAuthAuthorizationCode }
  | { ok: false; reason: 'not_found' | 'already_used' | 'expired' };

/**
 * Atomically consume an authorization code.
 *
 * Reads the row, then stamps `used_at` via a conditional UPDATE guarded by
 * `used_at IS NULL`. If the UPDATE changes zero rows, another request already
 * consumed it (replay) → `already_used`. Expiry is checked against `now`.
 *
 * This is the single chokepoint for one-shot + expiry enforcement; the token
 * handler must route every code through it.
 *
 * @param now - Unix seconds (caller passes the request's current time)
 */
export async function consumeAuthorizationCode(
  db: D1Database,
  code: string,
  now: number,
): Promise<ConsumeAuthorizationCodeResult> {
  const row = await db
    .prepare('SELECT * FROM oauth_authorization_codes WHERE code = ?')
    .bind(code)
    .first<OAuthAuthorizationCodeRow>();

  if (!row) return { ok: false, reason: 'not_found' };

  // Already consumed → replay attempt.
  if (row.used_at !== null) return { ok: false, reason: 'already_used' };

  // Expired (still mark used below would be wrong; just reject).
  if (row.expires_at <= now) return { ok: false, reason: 'expired' };

  // Atomic one-shot: only succeeds if used_at is still NULL.
  const result = await db
    .prepare(
      `UPDATE oauth_authorization_codes SET used_at = ? WHERE code = ? AND used_at IS NULL`,
    )
    .bind(now, code)
    .run();

  if ((result.meta.changes ?? 0) === 0) {
    // Lost the race — a concurrent exchange consumed it first.
    return { ok: false, reason: 'already_used' };
  }

  return { ok: true, code: rowToCode(row) };
}

// ─── Cleanup ────────────────────────────────────────────────

/**
 * Delete expired authorization codes. Intended for a future cron sweep
 * (see Fix_Auth_Cron_Cleanup.md follow-up). Returns the number of rows removed.
 */
export async function cleanupExpiredAuthorizationCodes(
  db: D1Database,
  now: number,
): Promise<number> {
  const result = await db
    .prepare('DELETE FROM oauth_authorization_codes WHERE expires_at < ?')
    .bind(now)
    .run();
  return result.meta.changes ?? 0;
}
