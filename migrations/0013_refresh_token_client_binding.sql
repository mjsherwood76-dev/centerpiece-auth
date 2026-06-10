-- Migration 0013: refresh-token client binding (codebase review C2/M3)
--
-- Binds third-party refresh tokens to the OAuth client they were issued to,
-- and records the scopes granted at issuance so the refresh grant can enforce
-- them. Without this, ANY registered active client could rotate ANY refresh
-- token (including first-party cp_refresh session tokens) into a valid
-- access + refresh token.
--
-- client_id:      oauth_third_party_clients.client_id the token was issued to
--                 via POST /oauth/token. NULL for first-party session tokens
--                 (login / register / cookie-refresh flows), which can never
--                 be rotated through the third-party grant.
-- granted_scopes: space-delimited scopes granted at issuance; carried forward
--                 across rotations. NULL for first-party tokens.
ALTER TABLE refresh_tokens ADD COLUMN client_id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN granted_scopes TEXT;
