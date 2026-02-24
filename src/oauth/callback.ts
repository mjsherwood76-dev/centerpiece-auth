/**
 * Shared OAuth Callback Handler
 *
 * All OAuth providers converge here after extracting the user profile.
 * This handler:
 *
 * 1. Upserts the user:
 *    - Find by oauth_accounts(provider, provider_account_id)
 *    - Or find by email + link if email_verified === true
 *    - Or create a new user
 * 2. Links OAuth account to user
 * 3. Ensures tenant_memberships row (role: customer only)
 * 4. Issues refresh token + authorization code
 * 5. Redirects to tenant with auth code
 *
 * Email linking rules (per Security Principles):
 * - If user exists with same email AND provider confirms email_verified → link
 * - If provider does NOT confirm email_verified → create separate user
 * - Apple: email is always verified; name only on first login
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import type { OAuthUserProfile } from './base.js';
import { oauthErrorRedirect } from './base.js';
import {
  generateRefreshToken,
  hashRefreshToken,
  generateAuthCode,
  hashAuthCode,
  generateUUID,
  buildRefreshCookieHeader,
} from '../crypto/refreshTokens.js';
import { validateRedirectUrl } from '../security/redirectValidator.js';

/**
 * Handle the shared OAuth callback logic after a provider extracts the user profile.
 *
 * @param request - The original callback request (for IP/UA headers)
 * @param env - Worker environment bindings
 * @param profile - Extracted user profile from the OAuth provider
 * @param tenantId - Tenant ID from the stored OAuth state
 * @param redirectUrl - Return URL from the stored OAuth state
 */
export async function handleOAuthCallback(
  request: Request,
  env: Env,
  profile: OAuthUserProfile,
  tenantId: string,
  redirectUrl: string
): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Validate redirect URL (stored in state, but re-validate for safety) ──
  const redirectValidation = await validateRedirectUrl(
    redirectUrl,
    env.TENANT_CONFIGS,
    env.ENVIRONMENT
  );
  if (!redirectValidation.valid) {
    return oauthErrorRedirect(env, tenantId, '', 'invalid_redirect');
  }

  // ── Resolve or create user ──
  let userId: string;

  try {
    userId = await resolveUser(db, profile);
  } catch (err) {
    console.error('OAuth user resolution failed:', err);
    return oauthErrorRedirect(env, tenantId, redirectUrl, 'oauth_failed');
  }

  // ── Ensure tenant membership (customer only — per security rules) ──
  const membershipId = generateUUID();
  await db.ensureMembership(membershipId, userId, tenantId);

  // ── Issue refresh token ──
  const refreshToken = generateRefreshToken();
  const refreshTokenHash = await hashRefreshToken(refreshToken);
  const familyId = generateUUID();
  const refreshTtlDays = parseInt(env.REFRESH_TOKEN_TTL_DAYS || '30', 10);
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + refreshTtlDays * 24 * 60 * 60;

  await db.insertRefreshToken({
    id: generateUUID(),
    user_id: userId,
    token_hash: refreshTokenHash,
    family_id: familyId,
    expires_at: refreshExpiresAt,
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For'),
    user_agent: request.headers.get('User-Agent'),
  });

  // ── Generate authorization code ──
  const authCode = generateAuthCode();
  const authCodeHash = await hashAuthCode(authCode);
  const codeTtlSeconds = parseInt(env.AUTH_CODE_TTL_SECONDS || '60', 10);
  const codeExpiresAt = Math.floor(Date.now() / 1000) + codeTtlSeconds;

  await db.insertAuthCode({
    code_hash: authCodeHash,
    user_id: userId,
    tenant_id: tenantId,
    redirect_origin: redirectValidation.origin,
    aud: 'storefront',
    expires_at: codeExpiresAt,
  });

  // ── Redirect with code ──
  const returnUrl = new URL(redirectUrl);
  const callbackUrl = new URL('/auth/callback', returnUrl.origin);
  callbackUrl.searchParams.set('code', authCode);
  callbackUrl.searchParams.set('returnTo', returnUrl.pathname + returnUrl.search);

  const refreshCookie = buildRefreshCookieHeader(refreshToken, refreshTtlDays, env.AUTH_DOMAIN);

  return new Response(null, {
    status: 302,
    headers: {
      Location: callbackUrl.toString(),
      'Set-Cookie': refreshCookie,
      'Cache-Control': 'no-store',
    },
  });
}

// ─── User Resolution ────────────────────────────────────────

/**
 * Resolve or create a user from an OAuth profile.
 *
 * Resolution order:
 * 1. Find existing OAuth link (provider + providerAccountId) → use that user
 * 2. Find user by email + email is verified by provider → link accounts
 * 3. Email not verified by provider → create new separate user
 * 4. No existing user → create new user
 *
 * @returns The user ID (existing or newly created)
 */
async function resolveUser(db: AuthDB, profile: OAuthUserProfile): Promise<string> {
  // 1. Check for existing OAuth account link
  const existingOAuth = await db.getOAuthAccount(profile.provider, profile.providerAccountId);
  if (existingOAuth) {
    // User already linked to this provider — update name/avatar if provided
    const user = await db.getUserById(existingOAuth.user_id);
    if (user) {
      // Update name if it was empty (e.g., Apple first-login name now available)
      if (profile.name && !user.name) {
        await db.updateUserName(user.id, profile.name);
      }
      // Update avatar if we have one and user doesn't
      if (profile.avatarUrl && !user.avatar_url) {
        await db.updateUserAvatar(user.id, profile.avatarUrl);
      }
    }
    return existingOAuth.user_id;
  }

  // 2. Check for existing user by email
  if (profile.email) {
    const existingUser = await db.getUserByEmail(profile.email);

    if (existingUser) {
      // Email linking rules (per Security Principles):
      // Only auto-link if the provider confirms email_verified === true
      if (profile.emailVerified) {
        // Link this OAuth provider to the existing user
        await db.upsertOAuthAccount({
          id: generateUUID(),
          user_id: existingUser.id,
          provider: profile.provider,
          provider_account_id: profile.providerAccountId,
        });

        // Update name/avatar if missing
        if (profile.name && !existingUser.name) {
          await db.updateUserName(existingUser.id, profile.name);
        }
        if (profile.avatarUrl && !existingUser.avatar_url) {
          await db.updateUserAvatar(existingUser.id, profile.avatarUrl);
        }

        // Mark email as verified if not already
        if (!existingUser.email_verified) {
          await db.markEmailVerified(existingUser.id);
        }

        return existingUser.id;
      } else {
        // Provider does NOT verify email — create separate user
        // The user can manually link accounts later from an authenticated session
        console.warn(
          `OAuth email linking skipped: provider ${profile.provider} did not verify email ${profile.email}`
        );
      }
    }
  }

  // 3. Create new user
  const newUserId = generateUUID();
  await db.insertUser({
    id: newUserId,
    email: profile.email,
    email_verified: profile.emailVerified,
    name: profile.name,
    avatar_url: profile.avatarUrl,
    password_hash: null, // OAuth-only account — no password
  });

  // Link OAuth account
  await db.upsertOAuthAccount({
    id: generateUUID(),
    user_id: newUserId,
    provider: profile.provider,
    provider_account_id: profile.providerAccountId,
  });

  return newUserId;
}
