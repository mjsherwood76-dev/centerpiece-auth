-- Migration 0011: Tenant Invites
--
-- Email-driven team invites (Fix_Team_Invites, ADR 020). A pending invite to a
-- brand-new person (no account yet) is its own record here — NOT a
-- `status='invited'` membership, because a brand-new invitee has no userId yet.
-- Acceptance (centerpiece-auth /accept-invite) creates the user + membership and
-- sets `accepted_at`. Existing accounts are auto-granted directly by platform-api
-- and never get a row here.
--
-- The plaintext token is NEVER stored — only its SHA-256 hash (`token_hash`),
-- per the repo token-security rule. Lookup is by hash; a row is single-use:
-- `accepted_at` is set on first successful acceptance and any subsequent
-- presentation is rejected. Invites expire at `expires_at` (created_at + 7d).
--
-- Re-invite after expiry: the UNIQUE(email, tenant_id, context, sub_role) row
-- would otherwise block a fresh invite once an old one expired unaccepted.
-- createInvite() PURGES any expired/unaccepted row for the same tuple before
-- inserting (operator-chosen auto-purge on re-invite).
--
-- Reversibility: purely additive (CREATE TABLE + indexes; no ALTER of existing
-- tables). Rollback = DROP TABLE tenant_invites, zero data-loss risk.
--
-- Apply MANUALLY (NOT `wrangler d1 migrations apply` — the auth migration
-- tracking table is empty and `apply` would re-run 0001–0010 and abort):
--   wrangler d1 execute centerpiece-auth-db-staging --env staging --remote --file=migrations/0011_tenant_invites.sql
--   wrangler d1 execute centerpiece-auth-db                          --remote --file=migrations/0011_tenant_invites.sql   (prod — operator AM cutover only)
--
-- Fix_Team_Invites Session 2.

CREATE TABLE IF NOT EXISTS tenant_invites (
  id          TEXT PRIMARY KEY,              -- uuid
  email       TEXT NOT NULL,                 -- lowercased
  tenant_id   TEXT NOT NULL,                 -- target tenant (or __platform__)
  context     TEXT NOT NULL CHECK(context IN ('seller','supplier','platform')),
  sub_role    TEXT NOT NULL,                 -- validated against CONTEXT_ROLES (no 'owner')
  token_hash  TEXT NOT NULL,                 -- SHA-256 hex of the single-use token; plaintext never stored
  invited_by  TEXT NOT NULL,                 -- userId of the granter
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL,                 -- created_at + 7d
  accepted_at TEXT,                          -- null until accepted (single-use)
  UNIQUE(email, tenant_id, context, sub_role)
);

CREATE INDEX IF NOT EXISTS idx_tenant_invites_tenant ON tenant_invites(tenant_id, accepted_at);
CREATE INDEX IF NOT EXISTS idx_tenant_invites_token  ON tenant_invites(token_hash);
