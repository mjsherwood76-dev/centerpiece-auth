-- 0008_pkce_sessions.sql
--
-- Server-side storage for the SPA's PKCE code_verifier.
--
-- Background: Chrome's bounce-tracking mitigation wipes first-party storage
-- (localStorage, sessionStorage, cookies) on cross-origin round-trips for
-- domains it flags as trackers. hub.centerpiecelab.com (.com TLD) trips this
-- heuristic; hub.centerpiecelab.dev does not. The verifier was being lost
-- between login() and the OAuth callback.
--
-- Solution: SPA POSTs the verifier to /api/pkce/init, gets back an opaque
-- session_id, passes session_id (not verifier) through the OAuth round-trip
-- via URL params. The auth Worker looks up the verifier server-side at token
-- exchange. URL params survive cross-origin navigation by definition; no
-- client storage is required.
--
-- The pkce_sessions table is the server-side store for these verifiers.
-- The pkce_session_id column on oauth_states carries the session reference
-- through the OAuth flow (SPA login → Google OAuth init → Google callback
-- → return redirect to hub).

CREATE TABLE IF NOT EXISTS pkce_sessions (
  id          TEXT PRIMARY KEY,            -- 32-char random hex session_id
  verifier    TEXT NOT NULL,               -- The SPA-generated code_verifier (plaintext)
  created_at  INTEGER NOT NULL,            -- unix epoch seconds
  expires_at  INTEGER NOT NULL             -- unix epoch seconds; ~10-min TTL
);

CREATE INDEX IF NOT EXISTS idx_pkce_sessions_expires_at
  ON pkce_sessions(expires_at);

-- Carry the session reference through the OAuth state row so the eventual
-- redirect back to hub.com/auth/callback can include the session_id.
ALTER TABLE oauth_states
  ADD COLUMN pkce_session_id TEXT NULL;
