/**
 * Tenant Invite Database Operations
 *
 * Standalone functions for all invite-related D1 queries (table: tenant_invites,
 * migration 0011). Each function takes D1Database as its first argument, mirroring
 * the db.memberships.ts style.
 *
 * Invites are single-use, hashed at rest (SHA-256), 7-day expiry. A pending
 * invite represents a brand-new person who has no account yet; existing accounts
 * are auto-granted directly by platform-api and never get a row here.
 *
 * Timestamps (created_at, expires_at, accepted_at) are TEXT in SQLite's
 * `datetime('now')` format ("YYYY-MM-DD HH:MM:SS"). Expiry comparisons are done
 * against `datetime('now')` inside SQL so the stored format and the comparison
 * format always match (no JS/SQLite format drift).
 *
 * @module db.invites
 */

import type { InviteRow } from './db.types.js';

/** Invite token expiry in days (single source of truth — ADR 020). */
export const INVITE_EXPIRY_DAYS = 7;

/**
 * Create a pending invite row.
 *
 * Purges any EXPIRED or UNACCEPTED row for the same
 * (email, tenant_id, context, sub_role) tuple first, so re-invite-after-expiry
 * works without tripping the UNIQUE constraint (ADR 020, operator-chosen
 * auto-purge). A still-pending (unexpired, unaccepted) row for the same tuple is
 * NOT purged — the caller (S3) must guard against duplicate live invites before
 * calling this; a UNIQUE violation here means "live invite already exists".
 *
 * `expiresAtSql` is set to created_at + INVITE_EXPIRY_DAYS via SQLite datetime
 * arithmetic so the stored format matches created_at exactly.
 */
export async function createInvite(
  db: D1Database,
  invite: {
    id: string;
    email: string;
    tenantId: string;
    context: 'seller' | 'supplier' | 'platform';
    subRole: string;
    tokenHash: string;
    invitedBy: string;
  },
): Promise<void> {
  const email = invite.email.toLowerCase();

  // Purge any expired/unaccepted row for the same tuple (re-invite after expiry).
  await db
    .prepare(
      `DELETE FROM tenant_invites
       WHERE email = ? AND tenant_id = ? AND context = ? AND sub_role = ?
         AND accepted_at IS NULL
         AND expires_at <= datetime('now')`
    )
    .bind(email, invite.tenantId, invite.context, invite.subRole)
    .run();

  await db
    .prepare(
      `INSERT INTO tenant_invites
         (id, email, tenant_id, context, sub_role, token_hash, invited_by, created_at, expires_at, accepted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now', ?), NULL)`
    )
    .bind(
      invite.id,
      email,
      invite.tenantId,
      invite.context,
      invite.subRole,
      invite.tokenHash,
      invite.invitedBy,
      `+${INVITE_EXPIRY_DAYS} days`,
    )
    .run();
}

/**
 * True iff a PENDING (unaccepted, unexpired) invite already exists for the tuple.
 * Used by the create path to reject a duplicate live invite up front.
 */
export async function hasPendingInvite(
  db: D1Database,
  email: string,
  tenantId: string,
  context: string,
  subRole: string,
): Promise<boolean> {
  const row = await db
    .prepare(
      `SELECT 1 FROM tenant_invites
       WHERE email = ? AND tenant_id = ? AND context = ? AND sub_role = ?
         AND accepted_at IS NULL
         AND expires_at > datetime('now')
       LIMIT 1`
    )
    .bind(email.toLowerCase(), tenantId, context, subRole)
    .first<{ 1: number }>();
  return row !== null;
}

/**
 * List pending (unaccepted, unexpired) invites for a tenant.
 * Used by GET /api/internal/invites/by-tenant.
 */
export async function getInvitesByTenant(
  db: D1Database,
  tenantId: string,
): Promise<InviteRow[]> {
  const result = await db
    .prepare(
      `SELECT * FROM tenant_invites
       WHERE tenant_id = ?
         AND accepted_at IS NULL
         AND expires_at > datetime('now')
       ORDER BY created_at DESC`
    )
    .bind(tenantId)
    .all<InviteRow>();
  return result.results;
}

/**
 * Look up an invite by token hash, regardless of accepted/expired state.
 * The accept flow inspects accepted_at / expires_at itself to return precise
 * errors (replay vs expired). Used by the public accept-invite flow.
 */
export async function getInviteByTokenHash(
  db: D1Database,
  tokenHash: string,
): Promise<InviteRow | null> {
  const row = await db
    .prepare('SELECT * FROM tenant_invites WHERE token_hash = ?')
    .bind(tokenHash)
    .first<InviteRow>();
  return row ?? null;
}

/**
 * Mark an invite accepted (single-use). Only updates a row that is still
 * unaccepted AND unexpired, so a concurrent double-accept or an expired token
 * cannot be marked. Returns true iff a row transitioned to accepted.
 */
export async function markInviteAccepted(
  db: D1Database,
  inviteId: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE tenant_invites SET accepted_at = datetime('now')
       WHERE id = ? AND accepted_at IS NULL AND expires_at > datetime('now')`
    )
    .bind(inviteId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

/**
 * Delete an invite by id (revoke a pending invite). Idempotent.
 * Returns true iff a row was deleted.
 */
export async function deleteInvite(
  db: D1Database,
  inviteId: string,
): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM tenant_invites WHERE id = ?')
    .bind(inviteId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

/**
 * Housekeeping: delete all expired, unaccepted invites. Returns rows removed.
 */
export async function deleteExpiredInvites(db: D1Database): Promise<number> {
  const result = await db
    .prepare(
      `DELETE FROM tenant_invites
       WHERE accepted_at IS NULL AND expires_at <= datetime('now')`
    )
    .run();
  return result.meta.changes ?? 0;
}
