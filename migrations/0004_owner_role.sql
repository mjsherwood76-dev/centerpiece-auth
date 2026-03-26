-- Migration 0004: Add 'owner' role to tenant_memberships
--
-- D1 does not support ALTER TABLE ... ADD CHECK.
-- Must recreate the table with expanded CHECK constraint.
--
-- Owner role: tenant-scoped ownership. Owner implies seller permissions
-- (enforced at JWT level in token.ts, not in schema).

-- Step 1: Create new table with expanded CHECK constraint
CREATE TABLE tenant_memberships_new (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  tenant_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('customer', 'seller', 'supplier', 'owner', 'platform_admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'invited')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, tenant_id, role)
);

-- Step 2: Copy all existing data
INSERT INTO tenant_memberships_new (id, user_id, tenant_id, role, status, created_at)
SELECT id, user_id, tenant_id, role, status, created_at FROM tenant_memberships;

-- Step 3: Drop old table
DROP TABLE tenant_memberships;

-- Step 4: Rename new table
ALTER TABLE tenant_memberships_new RENAME TO tenant_memberships;

-- Step 5: Recreate index
CREATE INDEX idx_memberships_user_id ON tenant_memberships(user_id);
