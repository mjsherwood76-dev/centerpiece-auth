-- Migration 0009: OAuth Third-Party Client Registry
--
-- Stores registered third-party OAuth clients (e.g., MCP bridges, integrations).
-- Each client has a hashed secret, allowed redirect URIs, and allowed scopes.
-- Platform admins register clients manually (no Dynamic Client Registration in v1).
--
-- Phase 3.18 Session 5.

CREATE TABLE IF NOT EXISTS oauth_third_party_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT NOT NULL,         -- PBKDF2-SHA-256 (same pattern as user passwords)
  client_name TEXT NOT NULL,
  redirect_uris_json TEXT NOT NULL,         -- JSON array; allow-list match required on authorize
  allowed_scopes_json TEXT NOT NULL,        -- JSON array, subset of scopes_supported
  created_at INTEGER NOT NULL,
  created_by_user_id TEXT NOT NULL,         -- platform admin user_id who registered the client
  status TEXT NOT NULL DEFAULT 'active',    -- 'active' | 'suspended' | 'revoked'
  contact_email TEXT
);

CREATE INDEX IF NOT EXISTS idx_oauth_third_party_clients_status
  ON oauth_third_party_clients(status);
