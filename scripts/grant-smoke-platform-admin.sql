-- Grant platform-admin (super admin) to smoke@centerpiecelab.com on staging.
--
-- The partial unique index `idx_one_owner_per_context` permits only one active
-- platform.owner row per __platform__. To make smoke the platform owner, mike's
-- existing row is suspended first. Reversible — see reverse-… script below.
--
-- Usage:
--   cd centerpiece-auth
--   npx wrangler d1 execute centerpiece-auth-db-staging --remote --file scripts/grant-smoke-platform-admin.sql

UPDATE tenant_memberships
SET status = 'suspended'
WHERE id = 'platform-owner-c60ecba8'
  AND user_id = 'c60ecba8-1601-4b7f-8598-2b89ae293239'
  AND tenant_id = '__platform__'
  AND context = 'platform'
  AND sub_role = 'owner';

INSERT INTO tenant_memberships (id, user_id, tenant_id, context, sub_role, status)
VALUES (
  'platform-owner-smoke',
  'c972266e-968b-4fa6-a217-4eeef3a2b039',
  '__platform__',
  'platform',
  'owner',
  'active'
);
