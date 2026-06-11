# AUTH_DB migrations

Migrations for `centerpiece-auth-db` (D1). Applied with wrangler's **tracked**
migration runner since 2026-06-10 (codebase review H5 remediation):

| Command | Target |
|---|---|
| `npm run db:migrate:local` | local miniflare DB |
| `npm run db:migrate:staging` | `centerpiece-auth-db-staging` (remote) |
| `npm run db:migrate:prod` | `centerpiece-auth-db` (remote) |

`wrangler d1 migrations apply` records each applied file in the `d1_migrations`
table and only applies new ones. **Do not** apply migration files with
`wrangler d1 execute --file=` anymore — that bypasses tracking and recreates
the drift this setup fixed.

## ⚠️ One-time cutover (per remote environment)

History: 0001–0012 were applied manually via `d1 execute --file=`, so the
tracking table is empty. Before the FIRST `db:migrate:staging` / `db:migrate:prod`:

1. **Inspect** what is actually applied (queries below).
2. **Edit** `scripts/backfill-d1-migrations.sql` if needed — delete rows for
   migrations the environment does NOT have. (As of 2026-06-10: staging is
   believed to have 0001–0012; production may not have 0011/0012 — the
   Team-Invites prod cutover was operator-gated.)
3. **Run the backfill** (records names only, executes nothing):
   ```
   npx wrangler d1 execute centerpiece-auth-db --env staging --remote --file=scripts/backfill-d1-migrations.sql
   npx wrangler d1 execute centerpiece-auth-db --remote --file=scripts/backfill-d1-migrations.sql
   ```
4. **Run the tracked apply** — it now applies only what's missing (e.g. 0013):
   ```
   npm run db:migrate:staging
   npm run db:migrate:prod
   ```

### Inspection queries (which migrations does this environment have?)

```sql
-- tables + indexes present
SELECT type, name FROM sqlite_master WHERE type IN ('table','index') ORDER BY name;
-- columns on the two most-altered tables
SELECT name FROM pragma_table_info('refresh_tokens');
SELECT name FROM pragma_table_info('oauth_states');
```

| Migration | Applied if… |
|---|---|
| 0001_initial_schema | table `users` exists |
| 0002_multi_role | `tenant_memberships` has column `context` |
| 0003_oauth_state_pkce | `oauth_states` has column `client_code_challenge` |
| 0004_owner_role | `SELECT sql FROM sqlite_master WHERE name='tenant_memberships'` mentions `'owner'` |
| 0005_permission_model_v2 | same DDL mentions the v2 sub-role set |
| 0006_fix_customer_membership_duplicates | index `idx_one_customer_per_tenant` exists |
| 0007_remember_device_and_login_iat | `refresh_tokens` has column `device_remembered` |
| 0008_pkce_sessions | table `pkce_sessions` exists |
| 0009_oauth_third_party_clients | table `oauth_third_party_clients` exists |
| 0010_oauth_authorization_codes | table `oauth_authorization_codes` exists |
| 0011_tenant_invites | table `tenant_invites` exists |
| 0012_email_verification_tokens | table `email_verification_tokens` exists |
| 0013_refresh_token_client_binding | `refresh_tokens` has column `client_id` |

## Numbering note

The 2026-06-10 codebase review observed `0011` missing (numbering skip at the
time). It has since been taken by `0011_tenant_invites.sql` (Team-Invites S2) —
the sequence 0001–0013 is now continuous.
