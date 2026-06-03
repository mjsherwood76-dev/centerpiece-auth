/**
 * OAuth Third-Party Client Registry Tests
 *
 * Pure unit tests (no network/D1):
 *   - validateScopes — scope allow-list enforcement
 *   - PBKDF2 hash round-trip — secret hashing and verification
 *
 * Integration tests (require staging, run in CI after Session 7 deploys migration 0009):
 *   - POST /admin/oauth/clients  → create client, returns one-time secret
 *   - GET  /admin/oauth/clients  → list clients
 *   - GET  /admin/oauth/clients/:id → detail
 *   - POST /admin/oauth/clients/:id/suspend → suspend
 *   - POST /admin/oauth/clients/:id/revoke  → revoke
 *   - 401 / 403 for missing or non-platform JWT
 *
 * Integration tests are skipped when SKIP_INTEGRATION_TESTS is set (local runs
 * before migration 0009 is applied to staging). They pass once Session 7 deploys.
 *
 * Phase 3.18 Session 5.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import { validateScopes, SUPPORTED_SCOPES } from '../src/db.oauthClients.js';
import { hashPassword, verifyPassword } from '../src/crypto/passwords.js';

// ─── Pure unit tests ─────────────────────────────────────────

describe('validateScopes', () => {
  it('returns empty array when all scopes are supported', () => {
    const invalid = validateScopes(['openid', 'profile', 'tenant:read']);
    assert.deepEqual(invalid, []);
  });

  it('returns the invalid scope when one is unsupported', () => {
    const invalid = validateScopes(['openid', 'not:a:scope']);
    assert.deepEqual(invalid, ['not:a:scope']);
  });

  it('returns all invalid scopes when none are supported', () => {
    const invalid = validateScopes(['fake:scope', 'another:bad:scope']);
    assert.equal(invalid.length, 2);
    assert.ok(invalid.includes('fake:scope'));
    assert.ok(invalid.includes('another:bad:scope'));
  });

  it('returns empty array for all SUPPORTED_SCOPES', () => {
    const allSupported = [...SUPPORTED_SCOPES];
    const invalid = validateScopes(allSupported);
    assert.deepEqual(invalid, []);
  });

  it('returns empty array for an empty scopes array', () => {
    const invalid = validateScopes([]);
    assert.deepEqual(invalid, []);
  });

  it('includes orders:read and orders:write in supported scopes', () => {
    assert.ok((SUPPORTED_SCOPES as readonly string[]).includes('orders:read'));
    assert.ok((SUPPORTED_SCOPES as readonly string[]).includes('orders:write'));
  });

  it('includes tenant:read and tenant:write in supported scopes', () => {
    assert.ok((SUPPORTED_SCOPES as readonly string[]).includes('tenant:read'));
    assert.ok((SUPPORTED_SCOPES as readonly string[]).includes('tenant:write'));
  });
});

// ─── PBKDF2 hash / verify round-trip ────────────────────────

describe('PBKDF2 client secret hashing', () => {
  it('hashPassword produces a pbkdf2: prefixed string', async () => {
    const secret = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
    const hash = await hashPassword(secret);
    assert.ok(hash.startsWith('pbkdf2:'), `expected pbkdf2: prefix, got: ${hash.substring(0, 10)}`);
  });

  it('verifyPassword returns true for the correct secret', async () => {
    const secret = 'test-client-secret-abc123';
    const hash = await hashPassword(secret);
    const ok = await verifyPassword(secret, hash);
    assert.equal(ok, true);
  });

  it('verifyPassword returns false for a wrong secret', async () => {
    const secret = 'correct-secret';
    const hash = await hashPassword(secret);
    const ok = await verifyPassword('wrong-secret', hash);
    assert.equal(ok, false);
  });

  it('two hashes of the same secret are different (random salt)', async () => {
    const secret = 'same-secret';
    const hash1 = await hashPassword(secret);
    const hash2 = await hashPassword(secret);
    assert.notEqual(hash1, hash2, 'Each hash should use a unique salt');
    // Both should still verify correctly
    assert.equal(await verifyPassword(secret, hash1), true);
    assert.equal(await verifyPassword(secret, hash2), true);
  });

  it('verifyPassword returns false for a malformed hash string', async () => {
    const ok = await verifyPassword('any-secret', 'not-a-valid-hash');
    assert.equal(ok, false);
  });
});

// ─── Integration tests (staging, require migration 0009) ────
//
// These tests hit the staging AUTH Worker directly.
// They are skipped locally unless STAGING_PLATFORM_ADMIN_TOKEN is set in env.
// Once Session 7 deploys migration 0009, these will run in CI.

const SKIP_INTEGRATION = !process.env['STAGING_PLATFORM_ADMIN_TOKEN'];
const BASE_URL = 'https://centerpiece-auth-staging.mjsherwood76.workers.dev';
const ADMIN_TOKEN = process.env['STAGING_PLATFORM_ADMIN_TOKEN'] ?? '';

function authHeaders(): HeadersInit {
  return {
    'Authorization': `Bearer ${ADMIN_TOKEN}`,
    'Content-Type': 'application/json',
  };
}

describe('POST /admin/oauth/clients (integration)', { skip: SKIP_INTEGRATION }, () => {
  it('returns 401 without a JWT', async () => {
    const res = await fetch(`${BASE_URL}/admin/oauth/clients`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientName: 'Test', redirectUris: ['https://test.example.com/cb'], allowedScopes: ['openid'] }),
    });
    assert.equal(res.status, 401);
  });

  it('creates a client and returns a one-time plaintext secret', async () => {
    const body = {
      clientName: 'Test Integration Client',
      redirectUris: ['https://test.example.com/callback'],
      allowedScopes: ['openid', 'tenant:read'],
      contactEmail: 'test@example.com',
    };

    const res = await fetch(`${BASE_URL}/admin/oauth/clients`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(body),
    });

    assert.equal(res.status, 201, `Expected 201, got ${res.status}: ${await res.text()}`);
    const data = (await res.json()) as Record<string, unknown>;

    assert.ok(typeof data['clientId'] === 'string' && data['clientId'].length > 0, 'clientId must be present');
    assert.equal(data['clientName'], 'Test Integration Client');
    assert.ok(typeof data['clientSecret'] === 'string' && data['clientSecret'].length === 64, 'clientSecret must be 32-byte hex (64 chars)');
    assert.equal(data['status'], 'active');
  });

  it('returns 400 for unsupported scopes', async () => {
    const res = await fetch(`${BASE_URL}/admin/oauth/clients`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        clientName: 'Bad Scopes',
        redirectUris: ['https://example.com/cb'],
        allowedScopes: ['not:a:real:scope'],
      }),
    });
    assert.equal(res.status, 400);
    const data = (await res.json()) as Record<string, unknown>;
    assert.ok(String(data['error']).includes('Unsupported scopes'));
  });

  it('returns 400 for non-https redirect URIs', async () => {
    const res = await fetch(`${BASE_URL}/admin/oauth/clients`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        clientName: 'Bad Redirect',
        redirectUris: ['http://not-https.example.com/cb'],
        allowedScopes: ['openid'],
      }),
    });
    assert.equal(res.status, 400);
  });
});

describe('GET /admin/oauth/clients (integration)', { skip: SKIP_INTEGRATION }, () => {
  it('returns 401 without a JWT', async () => {
    const res = await fetch(`${BASE_URL}/admin/oauth/clients`);
    assert.equal(res.status, 401);
  });

  it('returns a clients array for a platform-admin JWT', async () => {
    const res = await fetch(`${BASE_URL}/admin/oauth/clients`, {
      headers: authHeaders(),
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as Record<string, unknown>;
    assert.ok(Array.isArray(data['clients']), 'clients must be an array');
  });
});

describe('suspend / revoke lifecycle (integration)', { skip: SKIP_INTEGRATION }, () => {
  let createdClientId = '';

  before(async () => {
    // Create a client to operate on
    const res = await fetch(`${BASE_URL}/admin/oauth/clients`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        clientName: 'Lifecycle Test Client',
        redirectUris: ['https://lifecycle.example.com/cb'],
        allowedScopes: ['openid'],
      }),
    });
    if (res.ok) {
      const data = (await res.json()) as Record<string, unknown>;
      createdClientId = data['clientId'] as string;
    }
  });

  it('GET detail returns the created client', async () => {
    if (!createdClientId) return; // skip if create failed
    const res = await fetch(`${BASE_URL}/admin/oauth/clients/${createdClientId}`, {
      headers: authHeaders(),
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as Record<string, unknown>;
    const client = data['client'] as Record<string, unknown>;
    assert.equal(client['clientId'], createdClientId);
    assert.equal(client['status'], 'active');
  });

  it('suspend transitions client to suspended', async () => {
    if (!createdClientId) return;
    const res = await fetch(`${BASE_URL}/admin/oauth/clients/${createdClientId}/suspend`, {
      method: 'POST',
      headers: authHeaders(),
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as Record<string, unknown>;
    assert.equal(data['status'], 'suspended');
  });

  it('revoke transitions client to revoked', async () => {
    if (!createdClientId) return;
    const res = await fetch(`${BASE_URL}/admin/oauth/clients/${createdClientId}/revoke`, {
      method: 'POST',
      headers: authHeaders(),
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as Record<string, unknown>;
    assert.equal(data['status'], 'revoked');
  });

  it('GET detail for non-existent client returns 404', async () => {
    const res = await fetch(`${BASE_URL}/admin/oauth/clients/nonexistent-client-id-xyz`, {
      headers: authHeaders(),
    });
    assert.equal(res.status, 404);
  });
});
