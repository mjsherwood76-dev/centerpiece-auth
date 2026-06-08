/**
 * Auth Database Row Types
 *
 * Typed interfaces for all auth-related D1 tables.
 *
 * @module db.types
 */

export interface UserRow {
  id: string;
  email: string;
  email_verified: number; // SQLite boolean
  password_hash: string | null;
  name: string;
  avatar_url: string | null;
  created_at: string;
  updated_at: string;
}

export interface TenantMembershipRow {
  id: string;
  user_id: string;
  tenant_id: string;
  context: 'customer' | 'seller' | 'supplier' | 'platform';
  sub_role: 'owner' | 'manager' | 'designer' | 'analyst' | 'marketer'
    | 'merchandiser' | 'operator' | 'support' | 'operations' | 'finance' | null;
  status: 'active' | 'suspended' | 'invited';
  created_at: string;
}

export interface InviteRow {
  id: string;
  email: string;            // lowercased
  tenant_id: string;        // target tenant (or __platform__)
  context: 'seller' | 'supplier' | 'platform';
  sub_role: string;         // validated against CONTEXT_ROLES (no 'owner')
  token_hash: string;       // SHA-256 hex of the single-use token; plaintext never stored
  invited_by: string;       // userId of the granter
  created_at: string;       // datetime('now') text
  expires_at: string;       // created_at + 7d (ISO/datetime text)
  accepted_at: string | null; // null until accepted (single-use)
}

export interface OAuthAccountRow {
  id: string;
  user_id: string;
  provider: string;
  provider_account_id: string;
  created_at: string;
}

export interface AuthCodeRow {
  code_hash: string;
  user_id: string;
  tenant_id: string;
  redirect_origin: string;
  aud: 'storefront' | 'admin';
  expires_at: number;
  created_at: string;
  code_challenge: string | null;
  code_challenge_method: 'S256' | null;
  // Added by migration 0007 (Fix_Auth_Session_UX S3)
  refresh_token_id: string | null; // refresh_tokens.id; used to set JWT jti
}

export interface RefreshTokenRow {
  id: string;
  user_id: string;
  token_hash: string;
  family_id: string;
  expires_at: number;
  revoked_at: string | null;
  last_used_at: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  // Added by migration 0007 (Fix_Auth_Session_UX S3)
  device_remembered: number; // 0 | 1 — SQLite boolean
  device_label: string | null; // display-only UA parse; format may drift
  device_fingerprint: string | null; // sha256(UA | cfCountry)
  login_iat: number; // Unix seconds of the original login event; preserved across rotations
}
