-- Migration 0007: Remember-device columns + login_iat for Auth Session UX
-- Fix_Auth_Session_UX S3
--
-- Adds four columns to refresh_tokens:
--   device_remembered  — 1 if the user checked "Remember this device"; controls 90-day TTL
--   device_label       — display-only UA parse ("Chrome 120 on macOS"); format may drift
--   device_fingerprint — sha256(UA | cfCountry); stable per device within a country
--   login_iat          — Unix timestamp of the original login event; preserved across rotations;
--                        read by S1's refresh.ts to stamp login_iat into the JWT
--
-- Backfill: set login_iat = created_at epoch for existing rows so they don't break
-- post-migration (login_iat = 0 means "unknown"; backfill gives them a sane value).

ALTER TABLE refresh_tokens ADD COLUMN device_remembered INTEGER NOT NULL DEFAULT 0;
ALTER TABLE refresh_tokens ADD COLUMN device_label TEXT;
ALTER TABLE refresh_tokens ADD COLUMN device_fingerprint TEXT;
ALTER TABLE refresh_tokens ADD COLUMN login_iat INTEGER NOT NULL DEFAULT 0;

-- Backfill existing rows: derive login_iat from created_at so existing sessions
-- don't surface login_iat = 0 (which would look like epoch 1970 to S1/S5).
UPDATE refresh_tokens SET login_iat = CAST(strftime('%s', created_at) AS INTEGER) WHERE login_iat = 0;

-- oauth_states needs remember_device to carry the checkbox value through the
-- provider round trip (init handler → provider → callback handler).
ALTER TABLE oauth_states ADD COLUMN remember_device INTEGER NOT NULL DEFAULT 0;

-- auth_codes needs refresh_token_id so the token exchange handler can pass
-- refresh_token.id as the JWT jti, enabling S4's "Current device" badge to
-- match the active session row without an extra D1 lookup.
ALTER TABLE auth_codes ADD COLUMN refresh_token_id TEXT;
