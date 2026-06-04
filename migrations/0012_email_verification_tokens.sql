-- Migration 0012: Email Verification Tokens
--
-- One-time email-verification tokens minted when a customer registers on a
-- GATED tenant (Phase 3.25 Tenant Access Gating). The token is delivered as a
-- link in a tenant-branded verification email; following the link consumes the
-- token and sets users.email_verified = 1.
--
-- The plaintext token is NEVER stored — only its SHA-256 hash (`token_hash`),
-- per the repo token-security rule. Lookup is by hash; a row is one-shot:
-- `consumed_at` is set on first successful verification and any subsequent
-- presentation is rejected (replay protection). Tokens expire at `expires_at`.
--
-- Apply MANUALLY (NOT `wrangler d1 migrations apply` — the auth migration
-- tracking table is empty and `apply` would re-run 0001–0010 and abort):
--   wrangler d1 execute centerpiece-auth-db --env staging --file=migrations/0012_email_verification_tokens.sql
--   wrangler d1 execute centerpiece-auth-db            --file=migrations/0012_email_verification_tokens.sql
--
-- Phase 3.25 Session 2. The orchestrator applies this at deploy time (Session 7).

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,                  -- SHA-256 hex of the one-time token; plaintext never stored
  expires_at INTEGER NOT NULL,               -- Unix seconds
  consumed_at INTEGER,                       -- Unix seconds; set on first successful verification (one-shot)
  created_at INTEGER NOT NULL                -- Unix seconds
);

CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id
  ON email_verification_tokens(user_id);
