-- Migration 0003: Add PKCE + audience columns to oauth_states
--
-- Supports admin SPA OAuth flow where the SPA's code_challenge
-- must survive the OAuth redirect round trip and get stored
-- with the auth code.

ALTER TABLE oauth_states ADD COLUMN client_code_challenge TEXT;
ALTER TABLE oauth_states ADD COLUMN client_code_challenge_method TEXT CHECK(client_code_challenge_method IN ('S256'));
ALTER TABLE oauth_states ADD COLUMN audience TEXT;
