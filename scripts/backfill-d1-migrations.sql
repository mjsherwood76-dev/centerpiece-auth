-- ═══════════════════════════════════════════════════════════════════════════
-- ONE-TIME BACKFILL of wrangler's d1_migrations tracking table
-- (2026-06-10 codebase review H5 remediation)
--
-- ⚠️  READ migrations/README.md BEFORE RUNNING.
--
-- Context: migrations 0001–0012 were applied to staging/production manually
-- via `wrangler d1 execute --file=`, so the d1_migrations tracking table is
-- empty (or absent). `wrangler d1 migrations apply` would therefore try to
-- re-apply everything from 0001 and fail. This backfill records the
-- already-applied migrations WITHOUT executing them.
--
-- ⚠️  PER ENVIRONMENT: verify each migration listed below is ACTUALLY applied
--     (inspection queries in migrations/README.md) and DELETE the rows for any
--     that are not — then apply those for real with `npm run db:migrate:*`.
--     As of 2026-06-10: staging is believed to have 0001–0012; production may
--     NOT yet have 0011/0012 (Team-Invites prod cutover was operator-gated).
--
-- 0013 is intentionally NOT listed — it is the first migration meant to flow
-- through the new tracked path. (If you already applied 0013 manually, add
-- its row before running db:migrate.)
--
-- Usage:
--   staging: npx wrangler d1 execute centerpiece-auth-db --env staging --remote --file=scripts/backfill-d1-migrations.sql
--   prod:    npx wrangler d1 execute centerpiece-auth-db --remote --file=scripts/backfill-d1-migrations.sql
-- ═══════════════════════════════════════════════════════════════════════════

-- Exact DDL wrangler 4 uses for its tracking table.
CREATE TABLE IF NOT EXISTS d1_migrations(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT UNIQUE,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

INSERT OR IGNORE INTO d1_migrations (name) VALUES
  ('0001_initial_schema.sql'),
  ('0002_multi_role.sql'),
  ('0003_oauth_state_pkce.sql'),
  ('0004_owner_role.sql'),
  ('0005_permission_model_v2.sql'),
  ('0006_fix_customer_membership_duplicates.sql'),
  ('0007_remember_device_and_login_iat.sql'),
  ('0008_pkce_sessions.sql'),
  ('0009_oauth_third_party_clients.sql'),
  ('0010_oauth_authorization_codes.sql'),
  ('0011_tenant_invites.sql'),
  ('0012_email_verification_tokens.sql');
