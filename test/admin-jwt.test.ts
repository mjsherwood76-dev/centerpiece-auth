/**
 * Admin JWT Claims Tests — Staging Integration
 *
 * Tests Phase 2.3 Session 1 additions:
 * - Admin audience tokens include jti, roles, primaryTenantId
 * - PKCE enforcement for admin auth codes
 * - Storefront tokens remain unchanged (backward compatible)
 *
 * All tests run against the staging auth Worker:
 *   https://centerpiece-auth-staging.mjsherwood76.workers.dev
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { postForm, postJson, uniqueEmail, VALID_REDIRECT, getLocationParam, registerUser } from './helpers.js';

/** Admin redirect URL — points to admin staging domain. */
const ADMIN_REDIRECT = 'https://centerpiece-admin-staging.pages.dev/dashboard';

describe('Admin JWT Claims (Phase 2.3)', () => {
  describe('storefront tokens (backward compatibility)', () => {
    it('should NOT include jti, roles, or primaryTenantId on storefront tokens', async () => {
      const email = uniqueEmail();
      const { code } = await registerUser(email, 'StorefrontTest123!');
      assert.ok(code, 'should get auth code from registration');

      const redirectOrigin = new URL(VALID_REDIRECT).origin;
      const tenantId = '__unknown__';

      const res = await postJson('/api/token', {
        code,
        tenant_id: tenantId,
        redirect_origin: redirectOrigin,
      });

      assert.equal(res.status, 200);
      const body = (await res.json()) as Record<string, unknown>;
      const jwt = body.access_token as string;
      const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

      assert.equal(payload.aud, 'storefront');
      assert.equal(payload.jti, undefined, 'storefront token should NOT have jti');
      assert.equal(payload.roles, undefined, 'storefront token should NOT have roles');
      assert.equal(payload.primaryTenantId, undefined, 'storefront token should NOT have primaryTenantId');
    });
  });

  describe('admin tokens with audience=admin param', () => {
    it('should include jti, roles=[], primaryTenantId=null for user with no seller membership', async () => {
      const email = uniqueEmail();
      // Register via admin audience
      const res = await postForm('/api/login', {
        email,
        password: 'does-not-matter',
        tenant: 'test-tenant',
        redirect: VALID_REDIRECT,
        audience: 'admin',
      });
      // Login will fail since user doesn't exist yet — register first
      // Register the user first, then login with audience=admin
      await registerUser(email, 'AdminTest123!');

      const loginRes = await postForm('/api/login', {
        email,
        password: 'AdminTest123!',
        tenant: 'test-tenant',
        redirect: VALID_REDIRECT,
        audience: 'admin',
      });

      assert.equal(loginRes.status, 302, 'should redirect');
      const code = getLocationParam(loginRes, 'code');
      assert.ok(code, 'should include an authorization code');

      const redirectOrigin = new URL(VALID_REDIRECT).origin;
      const tenantId = '__unknown__';

      const tokenRes = await postJson('/api/token', {
        code,
        tenant_id: tenantId,
        redirect_origin: redirectOrigin,
      });

      assert.equal(tokenRes.status, 200);
      const body = (await tokenRes.json()) as Record<string, unknown>;
      const jwt = body.access_token as string;
      const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

      assert.equal(payload.aud, 'admin', 'JWT aud should be admin');
      assert.ok(payload.jti, 'admin token should have jti (UUID)');
      assert.ok(Array.isArray(payload.roles), 'admin token should have roles array');
      assert.deepEqual(payload.roles, [], 'roles should be empty for customer-only user');
      assert.equal(payload.primaryTenantId, null, 'primaryTenantId should be null for customer-only user');
    });

    it('should derive admin audience from admin domain redirect URL', async () => {
      const email = uniqueEmail();
      await registerUser(email, 'AdminDomainTest123!');

      const loginRes = await postForm('/api/login', {
        email,
        password: 'AdminDomainTest123!',
        tenant: 'test-tenant',
        redirect: ADMIN_REDIRECT,
      });

      assert.equal(loginRes.status, 302, 'should redirect');
      const code = getLocationParam(loginRes, 'code');
      assert.ok(code, 'should include an authorization code');

      const redirectOrigin = new URL(ADMIN_REDIRECT).origin;
      // Admin domain likely resolves to __unknown__ tenant since it's not a store domain
      const tenantId = '__unknown__';

      const tokenRes = await postJson('/api/token', {
        code,
        tenant_id: tenantId,
        redirect_origin: redirectOrigin,
      });

      assert.equal(tokenRes.status, 200);
      const body = (await tokenRes.json()) as Record<string, unknown>;
      const jwt = body.access_token as string;
      const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

      assert.equal(payload.aud, 'admin', 'JWT aud should be admin when redirect is admin domain');
      assert.ok(payload.jti, 'admin token should have jti');
      assert.ok(Array.isArray(payload.roles), 'admin token should have roles array');
    });
  });

  describe('PKCE enforcement for admin flows', () => {
    it('should accept admin auth code with valid PKCE code_verifier', async () => {
      const email = uniqueEmail();
      await registerUser(email, 'PkceTest123!');

      // Generate PKCE pair
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      // Login with code_challenge
      const loginRes = await postForm('/api/login', {
        email,
        password: 'PkceTest123!',
        tenant: 'test-tenant',
        redirect: VALID_REDIRECT,
        audience: 'admin',
        code_challenge: codeChallenge,
      });

      assert.equal(loginRes.status, 302, 'should redirect');
      const code = getLocationParam(loginRes, 'code');
      assert.ok(code, 'should include an authorization code');

      const redirectOrigin = new URL(VALID_REDIRECT).origin;
      const tenantId = '__unknown__';

      // Exchange with correct code_verifier
      const tokenRes = await postJson('/api/token', {
        code,
        tenant_id: tenantId,
        redirect_origin: redirectOrigin,
        code_verifier: codeVerifier,
      });

      assert.equal(tokenRes.status, 200, 'should succeed with valid code_verifier');
      const body = (await tokenRes.json()) as Record<string, unknown>;
      assert.ok(body.access_token, 'should return access_token');
    });

    it('should reject admin auth code with wrong code_verifier', async () => {
      const email = uniqueEmail();
      await registerUser(email, 'PkceWrongTest123!');

      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      const loginRes = await postForm('/api/login', {
        email,
        password: 'PkceWrongTest123!',
        tenant: 'test-tenant',
        redirect: VALID_REDIRECT,
        audience: 'admin',
        code_challenge: codeChallenge,
      });

      const code = getLocationParam(loginRes, 'code');
      assert.ok(code, 'should include an authorization code');

      const redirectOrigin = new URL(VALID_REDIRECT).origin;
      const tenantId = '__unknown__';

      // Exchange with WRONG code_verifier
      const tokenRes = await postJson('/api/token', {
        code,
        tenant_id: tenantId,
        redirect_origin: redirectOrigin,
        code_verifier: 'totally-wrong-verifier-value',
      });

      assert.equal(tokenRes.status, 400, 'should reject wrong code_verifier');
      const body = (await tokenRes.json()) as Record<string, string>;
      assert.ok(body.error.includes('code_verifier'), 'error should mention code_verifier');
    });

    it('should reject admin auth code with missing code_verifier when challenge was set', async () => {
      const email = uniqueEmail();
      await registerUser(email, 'PkceMissingTest123!');

      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      const loginRes = await postForm('/api/login', {
        email,
        password: 'PkceMissingTest123!',
        tenant: 'test-tenant',
        redirect: VALID_REDIRECT,
        audience: 'admin',
        code_challenge: codeChallenge,
      });

      const code = getLocationParam(loginRes, 'code');
      assert.ok(code, 'should include an authorization code');

      const redirectOrigin = new URL(VALID_REDIRECT).origin;
      const tenantId = '__unknown__';

      // Exchange WITHOUT code_verifier
      const tokenRes = await postJson('/api/token', {
        code,
        tenant_id: tenantId,
        redirect_origin: redirectOrigin,
        // no code_verifier
      });

      assert.equal(tokenRes.status, 400, 'should reject missing code_verifier');
      const body = (await tokenRes.json()) as Record<string, string>;
      assert.ok(body.error.includes('code_verifier'), 'error should mention code_verifier');
    });
  });
});

// ─── PKCE Helpers ───────────────────────────────────────────

/**
 * Generate a random code_verifier (43-128 chars, URL-safe).
 */
function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Generate S256 code_challenge from code_verifier.
 * BASE64URL(SHA256(code_verifier))
 */
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoded = new TextEncoder().encode(codeVerifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

function base64UrlEncode(buffer: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
