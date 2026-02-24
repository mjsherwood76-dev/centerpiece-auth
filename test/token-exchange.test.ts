/**
 * Token Exchange (Code → JWT) Tests — Staging Integration
 *
 * Tests the full flow:
 *   register → get auth code → POST /api/token → get JWT
 *
 * Also tests:
 * - Code replay fails (single-use)
 * - Wrong tenant fails
 * - Wrong origin fails
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { postJson, uniqueEmail, registerUser, VALID_REDIRECT } from './helpers.js';

describe('POST /api/token (code exchange)', () => {
  let authCode: string;
  const redirectOrigin = new URL(VALID_REDIRECT).origin;
  // Tenant ID is derived from the redirect URL hostname in the validator
  // For *.centerpiece.shop it will be '__unknown__' since there's no KV mapping
  const tenantId = '__unknown__';

  before(async () => {
    const email = uniqueEmail();
    const { code } = await registerUser(email, 'TokenTestPass123!');
    assert.ok(code, 'setup: should get auth code from registration');
    authCode = code!;
  });

  it('should exchange a valid code for a JWT access token', async () => {
    const res = await postJson('/api/token', {
      code: authCode,
      tenant_id: tenantId,
      redirect_origin: redirectOrigin,
    });

    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.ok(body.access_token, 'should return access_token');
    assert.equal(body.token_type, 'Bearer');
    assert.equal(body.expires_in, 900, 'should match ACCESS_TOKEN_TTL_SECONDS');

    // Verify JWT structure (3 dot-separated segments)
    const jwt = body.access_token as string;
    const parts = jwt.split('.');
    assert.equal(parts.length, 3, 'JWT should have 3 parts');

    // Decode payload (base64url)
    const payloadJson = Buffer.from(parts[1], 'base64url').toString();
    const payload = JSON.parse(payloadJson);
    assert.ok(payload.sub, 'JWT should have sub claim');
    assert.ok(payload.email, 'JWT should have email claim');
    assert.equal(payload.aud, 'storefront', 'JWT aud should be storefront');
    assert.ok(payload.exp > payload.iat, 'exp should be after iat');
  });

  it('should reject replayed code (single-use)', async () => {
    // authCode was already consumed above — replaying it should fail
    const res = await postJson('/api/token', {
      code: authCode,
      tenant_id: tenantId,
      redirect_origin: redirectOrigin,
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, string>;
    assert.ok(body.error, 'should return error');
  });

  it('should reject wrong tenant_id', async () => {
    // Register a fresh user to get a new code
    const { code } = await registerUser(uniqueEmail(), 'TokenTestPass123!');
    assert.ok(code);

    const res = await postJson('/api/token', {
      code,
      tenant_id: 'wrong-tenant-id',
      redirect_origin: redirectOrigin,
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, string>;
    assert.ok(body.error.includes('mismatch') || body.error.includes('Invalid'), 'should report mismatch');
  });

  it('should reject wrong redirect_origin', async () => {
    const { code } = await registerUser(uniqueEmail(), 'TokenTestPass123!');
    assert.ok(code);

    const res = await postJson('/api/token', {
      code,
      tenant_id: tenantId,
      redirect_origin: 'https://wrong-origin.com',
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, string>;
    assert.ok(body.error.includes('mismatch') || body.error.includes('Invalid'), 'should report origin mismatch');
  });

  it('should reject missing required fields', async () => {
    const res = await postJson('/api/token', {
      code: 'some-code',
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, string>;
    assert.ok(body.error.includes('Missing'));
  });

  it('should reject a completely bogus code', async () => {
    const res = await postJson('/api/token', {
      code: 'totally-fake-code-that-does-not-exist',
      tenant_id: tenantId,
      redirect_origin: redirectOrigin,
    });

    assert.equal(res.status, 400);
  });
});
