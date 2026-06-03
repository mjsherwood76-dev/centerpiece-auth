-- Migration 0010: OAuth Third-Party Authorization Codes
--
-- Short-lived authorization codes minted by the third-party OAuth consent flow
-- (GET /oauth/authorize → POST /oauth/authorize/decision). A client exchanges
-- the code for access + refresh tokens at POST /oauth/token.
--
-- The code itself is a 32-byte random hex secret used directly as the PRIMARY KEY
-- (per the Phase 3.18 plan schema). It is single-use: `used_at` is set on first
-- successful exchange; any subsequent presentation is rejected (replay protection).
-- Codes expire 5 minutes after issuance (`expires_at`).
--
-- PKCE: `code_challenge` stores the client's S256 challenge; the token endpoint
-- verifies BASE64URL(SHA256(code_verifier)) === code_challenge before issuing tokens.
--
-- Phase 3.18 Session 6.

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
  code TEXT PRIMARY KEY,                     -- 32-byte random hex; the code IS the secret
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  granted_scopes_json TEXT NOT NULL,         -- JSON array of granted scopes
  code_challenge TEXT NOT NULL,              -- PKCE S256 challenge
  redirect_uri TEXT NOT NULL,                -- exact redirect_uri the code was bound to
  expires_at INTEGER NOT NULL,              -- Unix seconds; now + 5min at issuance
  used_at INTEGER                            -- Unix seconds; set on first exchange (one-shot)
);

CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_expires_at
  ON oauth_authorization_codes(expires_at);
