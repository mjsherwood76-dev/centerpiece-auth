-- Centerpiece Auth — Initial Schema
-- D1 (SQLite) migration: 0001_initial_schema.sql
--
-- Tables: users, tenant_memberships, oauth_accounts, auth_codes, refresh_tokens

-- Users (platform-wide identity per FD-1)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,                    -- UUID
  email TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  password_hash TEXT,                     -- NULL for OAuth-only users
  name TEXT DEFAULT '',
  avatar_url TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Trigger: auto-update updated_at on user changes
CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
  AFTER UPDATE ON users
  FOR EACH ROW
BEGIN
  UPDATE users SET updated_at = datetime('now') WHERE id = OLD.id;
END;

-- Tenant memberships (per-tenant authorization per FD-1)
CREATE TABLE IF NOT EXISTS tenant_memberships (
  id TEXT PRIMARY KEY,                    -- UUID
  user_id TEXT NOT NULL REFERENCES users(id),
  tenant_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('customer', 'seller', 'platform_admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'invited')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user_tenant ON tenant_memberships(user_id, tenant_id);

-- OAuth account links
CREATE TABLE IF NOT EXISTS oauth_accounts (
  id TEXT PRIMARY KEY,                    -- UUID
  user_id TEXT NOT NULL REFERENCES users(id),
  provider TEXT NOT NULL,                 -- 'google', 'facebook', 'apple', 'microsoft'
  provider_account_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(provider, provider_account_id)
);
CREATE INDEX IF NOT EXISTS idx_oauth_provider ON oauth_accounts(provider, provider_account_id);

-- Authorization codes (single-use, short-lived)
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,             -- SHA-256 hash of the code (never store plaintext)
  user_id TEXT NOT NULL REFERENCES users(id),
  tenant_id TEXT NOT NULL,
  redirect_origin TEXT NOT NULL,          -- Origin that initiated the flow (validated at exchange)
  aud TEXT NOT NULL CHECK(aud IN ('storefront', 'admin')),
  expires_at INTEGER NOT NULL,            -- Unix timestamp, 60s TTL
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);

-- Refresh tokens (for rotation and revocation)
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY,                    -- UUID
  user_id TEXT NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL,
  family_id TEXT NOT NULL,                -- Token family for rotation detection
  expires_at INTEGER NOT NULL,            -- Unix timestamp
  revoked_at TEXT,                        -- NULL if active, datetime if revoked
  last_used_at TEXT,                      -- Last time this token was used for refresh
  ip TEXT,                                -- IP address at token creation
  user_agent TEXT,                        -- User-Agent at token creation
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);

-- OAuth state storage (CSRF protection, short-lived)
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  redirect_url TEXT NOT NULL,
  code_verifier TEXT NOT NULL,            -- PKCE code_verifier
  nonce TEXT,                             -- OIDC nonce (for ID token validation)
  provider TEXT NOT NULL,
  expires_at INTEGER NOT NULL,            -- Unix timestamp, 5-min TTL
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at);

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  token_hash TEXT PRIMARY KEY,            -- SHA-256 hash (never store plaintext)
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL,            -- Unix timestamp, 1-hour TTL
  used_at TEXT,                           -- NULL if unused
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_expires ON password_reset_tokens(expires_at);
