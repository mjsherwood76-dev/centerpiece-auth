-- Migration 0005: Permission Model v2 — Context + Sub-Role Architecture
--
-- Replaces flat `role` column with two-dimensional `context` + `sub_role` model.
-- D1 does not support ALTER TABLE ... ADD COLUMN with CHECK, so the table must be recreated.
--
-- Data transformation:
--   customer       → context='customer',  sub_role=NULL
--   seller         → context='seller',    sub_role='manager'
--   owner          → context='seller',    sub_role='owner'
--   supplier       → context='supplier',  sub_role='operator'
--   platform_admin → context='platform',  sub_role='owner'
--
-- Post-migration: run scripts/validate-permissions-v2.mjs to clean up
-- redundant seller/manager rows where user is also seller/owner.
--
-- IMPORTANT: This is a one-time migration. Take a D1 backup before running.

-- Step 1: Create new table with context + sub_role columns
CREATE TABLE tenant_memberships_new (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  tenant_id TEXT NOT NULL,
  context TEXT NOT NULL CHECK(context IN ('customer', 'seller', 'supplier', 'platform')),
  sub_role TEXT CHECK(sub_role IN (
    'owner', 'manager', 'designer', 'analyst', 'marketer',
    'merchandiser', 'operator',
    'support', 'operations', 'finance'
  )),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'invited')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),

  -- Customer context must have NULL sub_role; all other contexts must have a sub_role
  CHECK(
    (context = 'customer' AND sub_role IS NULL) OR
    (context != 'customer' AND sub_role IS NOT NULL)
  ),

  UNIQUE(user_id, tenant_id, context, sub_role)
);

-- Step 2: Migrate existing data with role → context + sub_role transformation

-- customer rows: context='customer', sub_role=NULL
INSERT INTO tenant_memberships_new (id, user_id, tenant_id, context, sub_role, status, created_at)
SELECT id, user_id, tenant_id, 'customer', NULL, status, created_at
FROM tenant_memberships WHERE role = 'customer';

-- seller rows: context='seller', sub_role='manager'
-- Rationale: seller was the base seller role with full day-to-day access.
-- 'manager' is the closest match (full ops minus tax/banking).
-- The validation script will remove redundant manager rows where user is also owner.
INSERT INTO tenant_memberships_new (id, user_id, tenant_id, context, sub_role, status, created_at)
SELECT id, user_id, tenant_id, 'seller', 'manager', status, created_at
FROM tenant_memberships WHERE role = 'seller';

-- owner rows: context='seller', sub_role='owner'
INSERT INTO tenant_memberships_new (id, user_id, tenant_id, context, sub_role, status, created_at)
SELECT id, user_id, tenant_id, 'seller', 'owner', status, created_at
FROM tenant_memberships WHERE role = 'owner';

-- supplier rows: context='supplier', sub_role='operator'
-- Rationale: supplier role was purely about fulfillment operations.
-- 'operator' maps directly to the supplier-specific ops sub-role.
INSERT INTO tenant_memberships_new (id, user_id, tenant_id, context, sub_role, status, created_at)
SELECT id, user_id, tenant_id, 'supplier', 'operator', status, created_at
FROM tenant_memberships WHERE role = 'supplier';

-- platform_admin rows: context='platform', sub_role='owner'
INSERT INTO tenant_memberships_new (id, user_id, tenant_id, context, sub_role, status, created_at)
SELECT id, user_id, tenant_id, 'platform', 'owner', status, created_at
FROM tenant_memberships WHERE role = 'platform_admin';

-- Step 3: Drop old table
DROP TABLE tenant_memberships;

-- Step 4: Rename new table
ALTER TABLE tenant_memberships_new RENAME TO tenant_memberships;

-- Step 5: Recreate indexes
CREATE INDEX idx_memberships_user_id ON tenant_memberships(user_id);
CREATE INDEX idx_memberships_tenant_context ON tenant_memberships(tenant_id, context);

-- Step 6: Partial unique index — at most one active owner per context per tenant
CREATE UNIQUE INDEX idx_one_owner_per_context
  ON tenant_memberships(tenant_id, context)
  WHERE sub_role = 'owner' AND status = 'active';
