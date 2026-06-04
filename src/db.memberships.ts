/**
 * Tenant Membership Database Operations
 *
 * Standalone functions for all membership-related D1 queries.
 * Each function takes D1Database as its first argument.
 *
 * @module db.memberships
 */

import type { TenantMembershipRow } from './db.types.js';

export async function getMembership(
  db: D1Database, userId: string, tenantId: string,
): Promise<TenantMembershipRow | null> {
  const result = await db
    .prepare('SELECT * FROM tenant_memberships WHERE user_id = ? AND tenant_id = ?')
    .bind(userId, tenantId)
    .first<TenantMembershipRow>();
  return result ?? null;
}

/**
 * Ensure a tenant membership exists for a user.
 * Only creates with context 'customer' and sub_role NULL — per security rules,
 * never auto-create seller or platform roles.
 *
 * Uses INSERT WHERE NOT EXISTS instead of ON CONFLICT because SQLite treats
 * NULLs as distinct in UNIQUE constraints — the ON CONFLICT clause on
 * (user_id, tenant_id, context, sub_role) never fires when sub_role is NULL,
 * causing duplicate customer rows on every login.
 */
export async function ensureMembership(
  db: D1Database, membershipId: string, userId: string, tenantId: string,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO tenant_memberships (id, user_id, tenant_id, context, sub_role, status)
       SELECT ?, ?, ?, 'customer', NULL, 'active'
       WHERE NOT EXISTS (
         SELECT 1 FROM tenant_memberships
         WHERE user_id = ? AND tenant_id = ? AND context = 'customer'
       )`
    )
    .bind(membershipId, userId, tenantId, userId, tenantId)
    .run();
}

/**
 * Get all active non-customer memberships for a user.
 * Used during admin token issuance to populate contexts + primaryTenantId.
 */
export async function getAdminMemberships(
  db: D1Database, userId: string,
): Promise<Array<{ tenant_id: string; context: string; sub_role: string }>> {
  const result = await db
    .prepare(
      `SELECT tenant_id, context, sub_role FROM tenant_memberships
       WHERE user_id = ? AND context != 'customer' AND status = 'active'
       ORDER BY created_at ASC`
    )
    .bind(userId)
    .all<{ tenant_id: string; context: string; sub_role: string }>();
  return result.results;
}

/**
 * True iff the user holds an ACTIVE `customer` membership on the given tenant.
 *
 * Context- and status-aware existence check used by the inline customer
 * storefront flow to tenant-scope forgot-password (a user may legitimately
 * have a global account but not be a customer of the requesting storefront).
 * A user can hold multiple membership rows per tenant (e.g. customer + seller),
 * so this is an EXISTS check, not a single-row `getMembership`.
 */
export async function hasCustomerMembership(
  db: D1Database, userId: string, tenantId: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      `SELECT 1 FROM tenant_memberships
       WHERE user_id = ? AND tenant_id = ? AND context = 'customer' AND status = 'active'
       LIMIT 1`
    )
    .bind(userId, tenantId)
    .first<{ 1: number }>();
  return result !== null;
}

/**
 * True iff the user holds an ACTIVE `customer` membership on ANY tenant.
 *
 * The tenant-agnostic counterpart to hasCustomerMembership(userId, tenantId).
 * Used by the auth-domain forgot-password guard, which has no single requesting
 * tenant in scope (the /forgot-password page is public, not storefront-bound) —
 * it only needs to know whether this account is a customer somewhere, to decide
 * whether it is a confirmed PURE-customer (customer-anywhere AND no privileged
 * context) who should reset via their storefront instead.
 */
export async function hasAnyCustomerMembership(
  db: D1Database, userId: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      `SELECT 1 FROM tenant_memberships
       WHERE user_id = ? AND context = 'customer' AND status = 'active'
       LIMIT 1`
    )
    .bind(userId)
    .first<{ 1: number }>();
  return result !== null;
}

/**
 * True iff the user holds ANY active privileged membership
 * (context IN seller / supplier / platform) on ANY tenant.
 *
 * Reuses getAdminMemberships, which already filters
 * `context != 'customer' AND status = 'active'` — i.e. exactly the privileged
 * set — rather than adding a parallel query. Used by the inline customer
 * storefront flow to wall privileged accounts out of customer auth/reset.
 */
export async function hasPrivilegedMembership(
  db: D1Database, userId: string,
): Promise<boolean> {
  const rows = await getAdminMemberships(db, userId);
  return rows.length > 0;
}

/**
 * Create a tenant membership with a specific role.
 * Used by POST /api/internal/memberships for seller/supplier provisioning.
 *
 * Unlike ensureMembership() which hard-codes 'customer', this method
 * accepts any allowed context + sub_role. Caller is responsible for authorization.
 *
 * UNIQUE(user_id, tenant_id, context, sub_role) prevents duplicates.
 */
export async function createMembership(
  db: D1Database,
  membershipId: string,
  userId: string,
  tenantId: string,
  context: 'seller' | 'supplier' | 'platform',
  subRole: string,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO tenant_memberships (id, user_id, tenant_id, context, sub_role, status)
       VALUES (?, ?, ?, ?, ?, 'active')`
    )
    .bind(membershipId, userId, tenantId, context, subRole)
    .run();
}

/**
 * Get all memberships for a user (all contexts, all tenants).
 * Used by GET /api/memberships endpoint.
 */
export async function getAllMemberships(
  db: D1Database, userId: string,
): Promise<TenantMembershipRow[]> {
  const result = await db
    .prepare(
      `SELECT * FROM tenant_memberships
       WHERE user_id = ?
       ORDER BY created_at ASC`
    )
    .bind(userId)
    .all<TenantMembershipRow>();
  return result.results;
}

/**
 * Get the active owner membership for a tenant in a given context.
 */
export async function getOwnerMembership(
  db: D1Database, tenantId: string, context: string,
): Promise<TenantMembershipRow | null> {
  const result = await db
    .prepare(
      `SELECT * FROM tenant_memberships
       WHERE tenant_id = ? AND context = ? AND sub_role = 'owner' AND status = 'active'
       LIMIT 1`
    )
    .bind(tenantId, context)
    .first<TenantMembershipRow>();
  return result ?? null;
}

/**
 * Delete a specific membership by user, tenant, context, and sub_role.
 */
export async function deleteMembership(
  db: D1Database, userId: string, tenantId: string, context: string, subRole: string,
): Promise<void> {
  await db
    .prepare(
      `DELETE FROM tenant_memberships WHERE user_id = ? AND tenant_id = ? AND context = ? AND sub_role = ?`
    )
    .bind(userId, tenantId, context, subRole)
    .run();
}

/**
 * Suspend all non-owner memberships for a user in a given context on a tenant.
 * Sets status to 'suspended'. Suspended memberships are excluded from JWT building.
 * Returns the number of rows affected.
 */
export async function suspendMemberships(
  db: D1Database, userId: string, tenantId: string, context: string,
): Promise<number> {
  const result = await db
    .prepare(
      `UPDATE tenant_memberships SET status = 'suspended'
       WHERE user_id = ? AND tenant_id = ? AND context = ? AND sub_role != 'owner' AND status = 'active'`
    )
    .bind(userId, tenantId, context)
    .run();
  return result.meta.changes ?? 0;
}

/**
 * Reactivate suspended memberships for a user in a given context on a tenant.
 * Sets status back to 'active'. Returns the number of rows affected.
 */
export async function reactivateMemberships(
  db: D1Database, userId: string, tenantId: string, context: string,
): Promise<number> {
  const result = await db
    .prepare(
      `UPDATE tenant_memberships SET status = 'active'
       WHERE user_id = ? AND tenant_id = ? AND context = ? AND status = 'suspended'`
    )
    .bind(userId, tenantId, context)
    .run();
  return result.meta.changes ?? 0;
}

/**
 * Get all non-customer memberships for a tenant, joined with user data.
 * Used by GET /api/internal/memberships/by-tenant endpoint.
 */
export async function getMembershipsByTenant(
  db: D1Database, tenantId: string,
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
  const result = await db
    .prepare(
      `SELECT tm.id, tm.user_id, u.email, u.name, tm.context, tm.sub_role, tm.status, tm.created_at
       FROM tenant_memberships tm
       JOIN users u ON tm.user_id = u.id
       WHERE tm.tenant_id = ? AND tm.context != 'customer'
       ORDER BY tm.created_at ASC`
    )
    .bind(tenantId)
    .all<{
      id: string;
      user_id: string;
      email: string;
      name: string;
      context: string;
      sub_role: string;
      status: string;
      created_at: string;
    }>();
  return result.results;
}

/**
 * Look up a user by email address.
 * Used by GET /api/internal/users/by-email endpoint.
 */
export async function getUserByEmailPublic(
  db: D1Database, email: string,
): Promise<{ id: string; email: string; name: string } | null> {
  const result = await db
    .prepare('SELECT id, email, name FROM users WHERE email = ? LIMIT 1')
    .bind(email.toLowerCase())
    .first<{ id: string; email: string; name: string }>();
  return result ?? null;
}

/**
 * Count active seller-owner memberships for a user.
 * Used to enforce the 5-tenant-per-user limit (seller ownership only).
 */
export async function countOwnerMemberships(
  db: D1Database, userId: string,
): Promise<number> {
  const result = await db
    .prepare(
      `SELECT COUNT(*) as count FROM tenant_memberships
       WHERE user_id = ? AND context = 'seller' AND sub_role = 'owner' AND status = 'active'`
    )
    .bind(userId)
    .first<{ count: number }>();
  return result?.count ?? 0;
}
