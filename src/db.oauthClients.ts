/**
 * OAuth Third-Party Client Registry — D1 helpers
 *
 * CRUD operations for the `oauth_third_party_clients` table added in
 * migration 0009. Used by the platform-admin OAuth client management
 * endpoints (Phase 3.18 Session 5).
 *
 * Secret hashing: reuses PBKDF2-SHA-256 (100k iterations) from
 * `src/crypto/passwords.ts` — same algorithm used for user passwords.
 *
 * @module db.oauthClients
 */

import { hashPassword, verifyPassword } from './crypto/passwords.js';

// ─── Types ──────────────────────────────────────────────────

export interface OAuthThirdPartyClientRow {
  client_id: string;
  client_secret_hash: string;
  client_name: string;
  redirect_uris_json: string;
  allowed_scopes_json: string;
  created_at: number;
  created_by_user_id: string;
  status: string;
  contact_email: string | null;
}

export interface OAuthThirdPartyClient {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  allowedScopes: string[];
  createdAt: number;
  createdByUserId: string;
  status: 'active' | 'suspended' | 'revoked';
  contactEmail: string | null;
}

// ─── Supported scopes ───────────────────────────────────────

/** Scopes advertised by the OAuth Authorization Server Metadata endpoint. */
export const SUPPORTED_SCOPES = [
  'openid',
  'profile',
  'email',
  'tenant:read',
  'tenant:write',
  'orders:read',
  'orders:write',
] as const;

export type SupportedScope = typeof SUPPORTED_SCOPES[number];

// ─── Helpers ────────────────────────────────────────────────

function rowToClient(row: OAuthThirdPartyClientRow): OAuthThirdPartyClient {
  return {
    clientId: row.client_id,
    clientName: row.client_name,
    redirectUris: JSON.parse(row.redirect_uris_json) as string[],
    allowedScopes: JSON.parse(row.allowed_scopes_json) as string[],
    createdAt: row.created_at,
    createdByUserId: row.created_by_user_id,
    status: row.status as 'active' | 'suspended' | 'revoked',
    contactEmail: row.contact_email,
  };
}

/**
 * Validate that every scope in `scopes` is a member of SUPPORTED_SCOPES.
 * Returns the invalid scopes (empty array = all valid).
 */
export function validateScopes(scopes: string[]): string[] {
  const supported = new Set<string>(SUPPORTED_SCOPES);
  return scopes.filter((s) => !supported.has(s));
}

// ─── CRUD helpers ───────────────────────────────────────────

/**
 * Create a new OAuth third-party client.
 *
 * Generates a random 32-byte plaintext secret, hashes it with PBKDF2-SHA-256,
 * stores the hash, and returns BOTH the client record and the one-time
 * plaintext secret. The plaintext secret is NEVER stored and cannot be
 * recovered after this call.
 *
 * @returns { client, plaintextSecret }
 */
export async function createClient(
  db: D1Database,
  params: {
    clientId: string;
    clientName: string;
    redirectUris: string[];
    allowedScopes: string[];
    createdByUserId: string;
    contactEmail?: string | null;
  },
): Promise<{ client: OAuthThirdPartyClient; plaintextSecret: string }> {
  // Generate 32-byte random secret as hex string
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const plaintextSecret = Array.from(secretBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const secretHash = await hashPassword(plaintextSecret);
  const now = Math.floor(Date.now() / 1000);

  await db
    .prepare(
      `INSERT INTO oauth_third_party_clients
         (client_id, client_secret_hash, client_name, redirect_uris_json, allowed_scopes_json,
          created_at, created_by_user_id, status, contact_email)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
    )
    .bind(
      params.clientId,
      secretHash,
      params.clientName,
      JSON.stringify(params.redirectUris),
      JSON.stringify(params.allowedScopes),
      now,
      params.createdByUserId,
      params.contactEmail ?? null,
    )
    .run();

  const client: OAuthThirdPartyClient = {
    clientId: params.clientId,
    clientName: params.clientName,
    redirectUris: params.redirectUris,
    allowedScopes: params.allowedScopes,
    createdAt: now,
    createdByUserId: params.createdByUserId,
    status: 'active',
    contactEmail: params.contactEmail ?? null,
  };

  return { client, plaintextSecret };
}

/**
 * Find a client by its client_id.
 * Returns null if not found.
 */
export async function findClientById(
  db: D1Database,
  clientId: string,
): Promise<OAuthThirdPartyClient | null> {
  const row = await db
    .prepare('SELECT * FROM oauth_third_party_clients WHERE client_id = ?')
    .bind(clientId)
    .first<OAuthThirdPartyClientRow>();

  return row ? rowToClient(row) : null;
}

/**
 * Verify a client_id + client_secret pair.
 *
 * Uses constant-time PBKDF2 comparison (via verifyPassword) to prevent
 * timing side-channel attacks.
 *
 * @returns true if the credentials are valid and the client is active.
 */
export async function verifyClientSecret(
  db: D1Database,
  clientId: string,
  plaintextSecret: string,
): Promise<boolean> {
  const row = await db
    .prepare(
      `SELECT client_secret_hash, status FROM oauth_third_party_clients WHERE client_id = ?`,
    )
    .bind(clientId)
    .first<{ client_secret_hash: string; status: string }>();

  if (!row || row.status !== 'active') return false;

  return verifyPassword(plaintextSecret, row.client_secret_hash);
}

/**
 * List all clients, optionally filtered by status.
 * Returns most-recently-created first.
 */
export async function listClients(
  db: D1Database,
  opts?: { status?: 'active' | 'suspended' | 'revoked' },
): Promise<OAuthThirdPartyClient[]> {
  let sql = 'SELECT * FROM oauth_third_party_clients';
  const params: string[] = [];

  if (opts?.status) {
    sql += ' WHERE status = ?';
    params.push(opts.status);
  }

  sql += ' ORDER BY created_at DESC';

  const result = params.length > 0
    ? await db.prepare(sql).bind(...params).all<OAuthThirdPartyClientRow>()
    : await db.prepare(sql).all<OAuthThirdPartyClientRow>();

  return result.results.map(rowToClient);
}

/**
 * Suspend an active client (status → 'suspended').
 * Idempotent: already suspended → no-op (returns true).
 * Revoked clients cannot be suspended (returns false).
 */
export async function suspendClient(
  db: D1Database,
  clientId: string,
): Promise<boolean> {
  const row = await db
    .prepare(`SELECT status FROM oauth_third_party_clients WHERE client_id = ?`)
    .bind(clientId)
    .first<{ status: string }>();

  if (!row) return false;
  if (row.status === 'revoked') return false;
  if (row.status === 'suspended') return true; // idempotent

  const result = await db
    .prepare(
      `UPDATE oauth_third_party_clients SET status = 'suspended' WHERE client_id = ? AND status = 'active'`,
    )
    .bind(clientId)
    .run();

  return (result.meta.changes ?? 0) > 0;
}

/**
 * Revoke a client permanently (status → 'revoked').
 * Idempotent: already revoked → no-op (returns true).
 * Revoked status is terminal — cannot be reversed.
 */
export async function revokeClient(
  db: D1Database,
  clientId: string,
): Promise<boolean> {
  const row = await db
    .prepare(`SELECT status FROM oauth_third_party_clients WHERE client_id = ?`)
    .bind(clientId)
    .first<{ status: string }>();

  if (!row) return false;
  if (row.status === 'revoked') return true; // idempotent

  const result = await db
    .prepare(
      `UPDATE oauth_third_party_clients SET status = 'revoked' WHERE client_id = ?`,
    )
    .bind(clientId)
    .run();

  return (result.meta.changes ?? 0) > 0;
}
