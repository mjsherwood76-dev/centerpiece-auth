-- Phase 2.3 Session 1 — Multi-role memberships + PKCE for admin flows
--
-- Changes:
-- 1. Recreate tenant_memberships with UNIQUE(user_id, tenant_id, role) instead of UNIQUE(user_id, tenant_id)
--    This allows a user to hold multiple roles (e.g., seller + supplier) for the same tenant.
--    Also adds 'supplier' to the role CHECK constraint for future Phase 3 use.
-- 2. Add code_challenge + code_challenge_method columns to auth_codes for PKCE support.

-- ── 1. Recreate tenant_memberships with relaxed UNIQUE constraint ──

CREATE TABLE tenant_memberships_new (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  tenant_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('customer', 'seller', 'supplier', 'platform_admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'invited')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, tenant_id, role)
);
INSERT INTO tenant_memberships_new SELECT * FROM tenant_memberships;
DROP TABLE tenant_memberships;
ALTER TABLE tenant_memberships_new RENAME TO tenant_memberships;
CREATE INDEX idx_memberships_user ON tenant_memberships(user_id);
CREATE INDEX idx_memberships_tenant ON tenant_memberships(tenant_id);

-- ── 2. Add PKCE columns to auth_codes ──

ALTER TABLE auth_codes ADD COLUMN code_challenge TEXT;
ALTER TABLE auth_codes ADD COLUMN code_challenge_method TEXT CHECK(code_challenge_method IN ('S256'));
