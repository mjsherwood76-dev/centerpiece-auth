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
}
