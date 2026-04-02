/**
 * D1 Database Abstraction Layer
 *
 * Typed helpers for all auth-related D1 operations.
 * IMPORTANT: Must run `PRAGMA foreign_keys = ON` on every D1 connection.
 *
 * This module keeps handlers clean and testable by encapsulating
 * all SQL in typed functions.
 */

// ─── Row Types (re-exported from db.types) ──────────────────

export type {
  UserRow,
  TenantMembershipRow,
  OAuthAccountRow,
  AuthCodeRow,
  RefreshTokenRow,
} from './db.types.js';

import type { UserRow, TenantMembershipRow, OAuthAccountRow, AuthCodeRow, RefreshTokenRow } from './db.types.js';
import * as memberships from './db.memberships.js';

// ─── Database Helper Class ──────────────────────────────────

export class AuthDB {
  constructor(private db: D1Database) {}

  /**
   * Enable foreign key enforcement for this connection.
   * D1 (SQLite) requires this per-connection.
   */
  async enableForeignKeys(): Promise<void> {
    await this.db.exec('PRAGMA foreign_keys = ON;');
  }

  // ─── Users ──────────────────────────────────────────────

  async getUserByEmail(email: string): Promise<UserRow | null> {
    const result = await this.db
      .prepare('SELECT * FROM users WHERE email = ?')
      .bind(email.toLowerCase())
      .first<UserRow>();
    return result ?? null;
  }

  async getUserById(id: string): Promise<UserRow | null> {
    const result = await this.db
      .prepare('SELECT * FROM users WHERE id = ?')
      .bind(id)
      .first<UserRow>();
    return result ?? null;
  }

  async insertUser(user: {
    id: string;
    email: string;
    password_hash?: string | null;
    name?: string;
    avatar_url?: string | null;
    email_verified?: boolean;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO users (id, email, email_verified, password_hash, name, avatar_url)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(
        user.id,
        user.email.toLowerCase(),
        user.email_verified ? 1 : 0,
        user.password_hash ?? null,
        user.name ?? '',
        user.avatar_url ?? null
      )
      .run();
  }

  async updateUserPassword(userId: string, passwordHash: string): Promise<void> {
    await this.db
      .prepare('UPDATE users SET password_hash = ? WHERE id = ?')
      .bind(passwordHash, userId)
      .run();
  }

  async updateUserName(userId: string, name: string): Promise<void> {
    await this.db
      .prepare('UPDATE users SET name = ? WHERE id = ?')
      .bind(name, userId)
      .run();
  }

  async updateUserAvatar(userId: string, avatarUrl: string): Promise<void> {
    await this.db
      .prepare('UPDATE users SET avatar_url = ? WHERE id = ?')
      .bind(avatarUrl, userId)
      .run();
  }

  async markEmailVerified(userId: string): Promise<void> {
    await this.db
      .prepare('UPDATE users SET email_verified = 1 WHERE id = ?')
      .bind(userId)
      .run();
  }

  // ─── Tenant Memberships (delegated to db.memberships) ────

  async getMembership(userId: string, tenantId: string): Promise<TenantMembershipRow | null> {
    return memberships.getMembership(this.db, userId, tenantId);
  }

  async ensureMembership(membershipId: string, userId: string, tenantId: string): Promise<void> {
    return memberships.ensureMembership(this.db, membershipId, userId, tenantId);
  }

  async getAdminMemberships(
    userId: string
  ): Promise<Array<{ tenant_id: string; context: string; sub_role: string }>> {
    return memberships.getAdminMemberships(this.db, userId);
  }

  async createMembership(
    membershipId: string,
    userId: string,
    tenantId: string,
    context: 'seller' | 'supplier' | 'platform',
    subRole: string,
  ): Promise<void> {
    return memberships.createMembership(this.db, membershipId, userId, tenantId, context, subRole);
  }

  async getAllMemberships(userId: string): Promise<TenantMembershipRow[]> {
    return memberships.getAllMemberships(this.db, userId);
  }

  async getOwnerMembership(tenantId: string, context: string): Promise<TenantMembershipRow | null> {
    return memberships.getOwnerMembership(this.db, tenantId, context);
  }

  async deleteMembership(userId: string, tenantId: string, context: string, subRole: string): Promise<void> {
    return memberships.deleteMembership(this.db, userId, tenantId, context, subRole);
  }

  async suspendMemberships(userId: string, tenantId: string, context: string): Promise<number> {
    return memberships.suspendMemberships(this.db, userId, tenantId, context);
  }

  async reactivateMemberships(userId: string, tenantId: string, context: string): Promise<number> {
    return memberships.reactivateMemberships(this.db, userId, tenantId, context);
  }

  async getMembershipsByTenant(
    tenantId: string
  ): Promise<Array<{
    id: string;
    user_id: string;
    email: string;
    name: string;
    context: string;
    sub_role: string;
    status: string;
    created_at: string;
  }>> {
    return memberships.getMembershipsByTenant(this.db, tenantId);
  }

  async getUserByEmailPublic(email: string): Promise<{ id: string; email: string; name: string } | null> {
    return memberships.getUserByEmailPublic(this.db, email);
  }

  async countOwnerMemberships(userId: string): Promise<number> {
    return memberships.countOwnerMemberships(this.db, userId);
  }

  // ─── OAuth Accounts ─────────────────────────────────────

  async getOAuthAccount(
    provider: string,
    providerAccountId: string
  ): Promise<OAuthAccountRow | null> {
    const result = await this.db
      .prepare('SELECT * FROM oauth_accounts WHERE provider = ? AND provider_account_id = ?')
      .bind(provider, providerAccountId)
      .first<OAuthAccountRow>();
    return result ?? null;
  }

  async upsertOAuthAccount(account: {
    id: string;
    user_id: string;
    provider: string;
    provider_account_id: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO oauth_accounts (id, user_id, provider, provider_account_id)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(provider, provider_account_id) DO UPDATE SET user_id = excluded.user_id`
      )
      .bind(account.id, account.user_id, account.provider, account.provider_account_id)
      .run();
  }

  // ─── Auth Codes ─────────────────────────────────────────

  async insertAuthCode(code: {
    code_hash: string;
    user_id: string;
    tenant_id: string;
    redirect_origin: string;
    aud: 'storefront' | 'admin';
    expires_at: number;
    code_challenge?: string | null;
    code_challenge_method?: 'S256' | null;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO auth_codes (code_hash, user_id, tenant_id, redirect_origin, aud, expires_at, code_challenge, code_challenge_method)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        code.code_hash,
        code.user_id,
        code.tenant_id,
        code.redirect_origin,
        code.aud,
        code.expires_at,
        code.code_challenge ?? null,
        code.code_challenge_method ?? null
      )
      .run();
  }

  /**
   * Consume an auth code — returns the row and deletes it atomically.
   * Returns null if the code doesn't exist or is expired.
   */
  async consumeAuthCode(codeHash: string): Promise<AuthCodeRow | null> {
    const row = await this.db
      .prepare('SELECT * FROM auth_codes WHERE code_hash = ?')
      .bind(codeHash)
      .first<AuthCodeRow>();
    if (!row) return null;

    // Delete immediately (single-use)
    await this.db
      .prepare('DELETE FROM auth_codes WHERE code_hash = ?')
      .bind(codeHash)
      .run();

    return row;
  }

  /**
   * Clean up expired auth codes.
   */
  async cleanupExpiredCodes(): Promise<number> {
    const now = Math.floor(Date.now() / 1000);
    const result = await this.db
      .prepare('DELETE FROM auth_codes WHERE expires_at < ?')
      .bind(now)
      .run();
    return result.meta.changes ?? 0;
  }

  // ─── Refresh Tokens ─────────────────────────────────────

  async insertRefreshToken(token: {
    id: string;
    user_id: string;
    token_hash: string;
    family_id: string;
    expires_at: number;
    ip?: string | null;
    user_agent?: string | null;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, ip, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        token.id,
        token.user_id,
        token.token_hash,
        token.family_id,
        token.expires_at,
        token.ip ?? null,
        token.user_agent ?? null
      )
      .run();
  }

  async getRefreshTokenByHash(tokenHash: string): Promise<RefreshTokenRow | null> {
    const result = await this.db
      .prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?')
      .bind(tokenHash)
      .first<RefreshTokenRow>();
    return result ?? null;
  }

  /**
   * Rotate a refresh token: revoke old one, issue new one in same family.
   * Returns false if the old token was already revoked (theft detection).
   */
  async rotateRefreshToken(
    oldTokenHash: string,
    newToken: {
      id: string;
      user_id: string;
      token_hash: string;
      family_id: string;
      expires_at: number;
      ip?: string | null;
      user_agent?: string | null;
    }
  ): Promise<{ success: boolean; reuseDetected: boolean }> {
    const existing = await this.getRefreshTokenByHash(oldTokenHash);
    if (!existing) {
      return { success: false, reuseDetected: false };
    }

    // Reuse detection: if the token was already revoked, someone stole it
    if (existing.revoked_at !== null) {
      // Revoke entire family
      await this.revokeRefreshTokenFamily(existing.family_id);
      return { success: false, reuseDetected: true };
    }

    // Revoke old token
    await this.db
      .prepare(
        `UPDATE refresh_tokens SET revoked_at = datetime('now'), last_used_at = datetime('now')
         WHERE token_hash = ?`
      )
      .bind(oldTokenHash)
      .run();

    // Insert new token
    await this.insertRefreshToken(newToken);

    return { success: true, reuseDetected: false };
  }

  /**
   * Revoke ALL refresh tokens in a family (theft detection response).
   */
  async revokeRefreshTokenFamily(familyId: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE refresh_tokens SET revoked_at = datetime('now')
         WHERE family_id = ? AND revoked_at IS NULL`
      )
      .bind(familyId)
      .run();
  }

  /**
   * Revoke ALL refresh tokens for a user (logout-all).
   */
  async revokeAllRefreshTokensForUser(userId: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE refresh_tokens SET revoked_at = datetime('now')
         WHERE user_id = ? AND revoked_at IS NULL`
      )
      .bind(userId)
      .run();
  }

  /**
   * Revoke a single refresh token (logout).
   */
  async revokeRefreshToken(tokenHash: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE refresh_tokens SET revoked_at = datetime('now')
         WHERE token_hash = ? AND revoked_at IS NULL`
      )
      .bind(tokenHash)
      .run();
  }

  // ─── Password Reset Tokens ─────────────────────────────

  async insertPasswordResetToken(token: {
    token_hash: string;
    user_id: string;
    expires_at: number;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO password_reset_tokens (token_hash, user_id, expires_at)
         VALUES (?, ?, ?)`
      )
      .bind(token.token_hash, token.user_id, token.expires_at)
      .run();
  }

  async consumePasswordResetToken(
    tokenHash: string
  ): Promise<{ user_id: string; expires_at: number } | null> {
    const row = await this.db
      .prepare(
        'SELECT user_id, expires_at FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL'
      )
      .bind(tokenHash)
      .first<{ user_id: string; expires_at: number }>();
    if (!row) return null;

    await this.db
      .prepare(`UPDATE password_reset_tokens SET used_at = datetime('now') WHERE token_hash = ?`)
      .bind(tokenHash)
      .run();

    return row;
  }

  // ─── OAuth States ───────────────────────────────────────

  async insertOAuthState(state: {
    state: string;
    tenant_id: string;
    redirect_url: string;
    code_verifier: string;
    nonce: string | null;
    provider: string;
    expires_at: number;
    client_code_challenge?: string | null;
    client_code_challenge_method?: 'S256' | null;
    audience?: string | null;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO oauth_states (state, tenant_id, redirect_url, code_verifier, nonce, provider, expires_at, client_code_challenge, client_code_challenge_method, audience)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        state.state,
        state.tenant_id,
        state.redirect_url,
        state.code_verifier,
        state.nonce,
        state.provider,
        state.expires_at,
        state.client_code_challenge ?? null,
        state.client_code_challenge_method ?? null,
        state.audience ?? null
      )
      .run();
  }

  async consumeOAuthState(
    stateValue: string
  ): Promise<{
    tenant_id: string;
    redirect_url: string;
    code_verifier: string;
    nonce: string | null;
    provider: string;
    expires_at: number;
    client_code_challenge: string | null;
    client_code_challenge_method: 'S256' | null;
    audience: string | null;
  } | null> {
    const row = await this.db
      .prepare('SELECT * FROM oauth_states WHERE state = ?')
      .bind(stateValue)
      .first<{
        state: string;
        tenant_id: string;
        redirect_url: string;
        code_verifier: string;
        nonce: string | null;
        provider: string;
        expires_at: number;
        client_code_challenge: string | null;
        client_code_challenge_method: 'S256' | null;
        audience: string | null;
      }>();
    if (!row) return null;

    await this.db.prepare('DELETE FROM oauth_states WHERE state = ?').bind(stateValue).run();

    return row;
  }

  /**
   * Clean up expired OAuth states.
   */
  async cleanupExpiredOAuthStates(): Promise<number> {
    const now = Math.floor(Date.now() / 1000);
    const result = await this.db
      .prepare('DELETE FROM oauth_states WHERE expires_at < ?')
      .bind(now)
      .run();
    return result.meta.changes ?? 0;
  }

  // ─── Generic Query Helpers ──────────────────────────────

  /**
   * Execute a raw SQL query and return the first result row.
   * Uses prepared statements to prevent SQL injection.
   */
  async raw<T>(sql: string, params: unknown[]): Promise<T | null> {
    let stmt = this.db.prepare(sql);
    if (params.length > 0) {
      stmt = stmt.bind(...params);
    }
    const result = await stmt.first<T>();
    return result ?? null;
  }

  /**
   * Execute a raw SQL query and return all result rows.
   * Uses prepared statements to prevent SQL injection.
   */
  async rawAll<T>(sql: string, params: unknown[]): Promise<T[]> {
    let stmt = this.db.prepare(sql);
    if (params.length > 0) {
      stmt = stmt.bind(...params);
    }
    const result = await stmt.all<T>();
    return result.results;
  }
}

// ─── TENANTS_DB Queries (read-only, separate D1 binding) ──

/**
 * Look up tenant names and domains from TENANTS_DB.
 * Returns a Map of tenantId → { name, domain } for active tenants found.
 * Tenants not found or not active are omitted from the result.
 *
 * @param tenantsDb - The TENANTS_DB D1 binding (read-only)
 * @param tenantIds - Array of tenant IDs to look up
 */
export async function getTenantNames(
  tenantsDb: D1Database,
  tenantIds: string[],
): Promise<Map<string, { name: string; domain: string }>> {
  const result = new Map<string, { name: string; domain: string }>();
  if (tenantIds.length === 0) return result;

  const placeholders = tenantIds.map(() => '?').join(', ');
  const rows = await tenantsDb
    .prepare(`SELECT id, name, domain FROM tenants WHERE id IN (${placeholders}) AND status = 'active'`)
    .bind(...tenantIds)
    .all<{ id: string; name: string; domain: string }>();

  for (const row of rows.results) {
    result.set(row.id, { name: row.name, domain: row.domain });
  }

  return result;
}
