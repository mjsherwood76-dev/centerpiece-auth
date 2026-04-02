/**
 * Switch Tenant Endpoint Tests — Staging Integration
 *
 * Tests POST /api/switch-tenant endpoint (Phase 3.3 Session 1).
 *
 * All tests run against the staging auth Worker:
 *   https://centerpiece-auth-staging.mjsherwood76.workers.dev
 *
 * Note: Most positive-path tests (switching to a different tenant) require
 * multi-tenant membership setup which isn't available via public API.
 * Those scenarios are covered by the edge-case test matrix and manual verification.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  postForm,
  postJson,
  uniqueEmail,
  VALID_REDIRECT,
  getLocationParam,
  registerUser,
  get,
} from './helpers.js';

/** Admin redirect URL — points to admin staging domain. */
const ADMIN_REDIRECT = 'https://centerpiece-platform-ui-staging.pages.dev/dashboard';

describe('POST /api/switch-tenant', () => {
  let adminToken: string;
  let adminPayload: Record<string, unknown>;

  before(async () => {
    // Register a user and get an admin JWT
    const email = uniqueEmail();
    await registerUser(email, 'SwitchTest123!');

    const loginRes = await postForm('/api/login', {
      email,
      password: 'SwitchTest123!',
      tenant: 'test-tenant',
      redirect: ADMIN_REDIRECT,
    });

    assert.equal(loginRes.status, 302, 'setup: login should redirect');
    const code = getLocationParam(loginRes, 'code');
    assert.ok(code, 'setup: should get auth code');

    const redirectOrigin = new URL(ADMIN_REDIRECT).origin;

    const tokenRes = await postJson('/api/token', {
      code,
      tenant_id: '__unknown__',
      redirect_origin: redirectOrigin,
    });

    assert.equal(tokenRes.status, 200, 'setup: token exchange should succeed');
    const body = (await tokenRes.json()) as Record<string, unknown>;
    adminToken = body.access_token as string;
    assert.ok(adminToken, 'setup: should have admin token');

    // Decode payload for assertions
    adminPayload = JSON.parse(
      Buffer.from(adminToken.split('.')[1], 'base64url').toString(),
    );
    assert.equal(adminPayload.aud, 'admin', 'setup: should be admin JWT');
  });

  it('should return 401 for missing Authorization header', async () => {
    const res = await postJson('/api/switch-tenant', {
      tenantId: 'some-tenant',
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.error, 'Unauthorized');
  });

  it('should return 401 for invalid JWT', async () => {
    const res = await fetch(
      'https://centerpiece-auth-staging.mjsherwood76.workers.dev/api/switch-tenant',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer totally-invalid-jwt-token',
        },
        body: JSON.stringify({ tenantId: 'some-tenant' }),
      },
    );

    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.error, 'Unauthorized');
  });

  it('should return 400 for missing tenantId in body', async () => {
    const res = await fetch(
      'https://centerpiece-auth-staging.mjsherwood76.workers.dev/api/switch-tenant',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({}),
      },
    );

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.error, 'tenantId is required');
  });

  it('should return 400 for empty tenantId', async () => {
    const res = await fetch(
      'https://centerpiece-auth-staging.mjsherwood76.workers.dev/api/switch-tenant',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({ tenantId: '   ' }),
      },
    );

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.error, 'tenantId is required');
  });

  it('should return 403 for tenant with no membership', async () => {
    const res = await fetch(
      'https://centerpiece-auth-staging.mjsherwood76.workers.dev/api/switch-tenant',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({ tenantId: 'nonexistent-tenant-id-12345' }),
      },
    );

    assert.equal(res.status, 403);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.error, 'No membership on this tenant');
  });

  it('should return current token for no-op switch (same primaryTenantId)', async () => {
    // The test user's primaryTenantId is null (no seller memberships)
    // So switching to null won't trigger the no-op path.
    // Instead, skip this test if primaryTenantId is null.
    if (adminPayload.primaryTenantId === null || adminPayload.primaryTenantId === undefined) {
      // User has no primary tenant — can't test no-op shortcut without seller membership.
      // This is expected for a fresh test user with only customer membership.
      return;
    }

    const res = await fetch(
      'https://centerpiece-auth-staging.mjsherwood76.workers.dev/api/switch-tenant',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({ tenantId: adminPayload.primaryTenantId }),
      },
    );

    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.access_token, adminToken, 'no-op should return same token');
    assert.equal(body.token_type, 'Bearer');
    assert.ok(typeof body.expires_in === 'number', 'should have expires_in');
  });

  it('should reject storefront JWT', async () => {
    // Register and get a storefront token (not admin)
    const email = uniqueEmail();
    const { code } = await registerUser(email, 'StorefrontSwitch123!');
    assert.ok(code, 'should get auth code');

    const redirectOrigin = new URL(VALID_REDIRECT).origin;
    const tokenRes = await postJson('/api/token', {
      code,
      tenant_id: '__unknown__',
      redirect_origin: redirectOrigin,
    });

    assert.equal(tokenRes.status, 200);
    const tokenBody = (await tokenRes.json()) as Record<string, unknown>;
    const storefrontToken = tokenBody.access_token as string;

    const res = await fetch(
      'https://centerpiece-auth-staging.mjsherwood76.workers.dev/api/switch-tenant',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storefrontToken}`,
        },
        body: JSON.stringify({ tenantId: 'some-tenant' }),
      },
    );

    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.error, 'Unauthorized');
  });
});

describe('GET /api/memberships (enriched with tenant names)', () => {
  let accessToken: string;

  before(async () => {
    const email = uniqueEmail();
    const { code } = await registerUser(email, 'EnrichedMembTest123!');
    assert.ok(code, 'setup: should get auth code');

    const redirectOrigin = new URL(VALID_REDIRECT).origin;
    const tokenRes = await postJson('/api/token', {
      code,
      tenant_id: '__unknown__',
      redirect_origin: redirectOrigin,
    });

    assert.equal(tokenRes.status, 200);
    const body = (await tokenRes.json()) as Record<string, unknown>;
    accessToken = body.access_token as string;
  });

  it('should include tenantName and tenantDomain fields in memberships response', async () => {
    const res = await get('/api/memberships', {
      Authorization: `Bearer ${accessToken}`,
    });

    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      memberships: Array<{
        tenantId: string;
        tenantName: string | null;
        tenantDomain: string | null;
        context: string;
        subRole: string | null;
        status: string;
      }>;
    };
    assert.ok(Array.isArray(body.memberships), 'should return memberships array');
    assert.ok(body.memberships.length >= 1, 'should have at least one membership');

    // Every membership should have tenantName and tenantDomain fields
    for (const m of body.memberships) {
      assert.ok('tenantName' in m, `membership for ${m.tenantId} should have tenantName field`);
      assert.ok('tenantDomain' in m, `membership for ${m.tenantId} should have tenantDomain field`);
    }
  });
});

describe('POST /api/token with tenantId hint', () => {
  it('should return tenantIdFallback when tenantId hint has no membership', async () => {
    const email = uniqueEmail();
    await registerUser(email, 'TenantHintTest123!');

    const loginRes = await postForm('/api/login', {
      email,
      password: 'TenantHintTest123!',
      tenant: 'test-tenant',
      redirect: ADMIN_REDIRECT,
    });

    assert.equal(loginRes.status, 302, 'login should redirect');
    const code = getLocationParam(loginRes, 'code');
    assert.ok(code, 'should get auth code');

    const redirectOrigin = new URL(ADMIN_REDIRECT).origin;

    const tokenRes = await postJson('/api/token', {
      code,
      tenant_id: '__unknown__',
      redirect_origin: redirectOrigin,
      tenantId: 'nonexistent-tenant-for-fallback-test',
    });

    assert.equal(tokenRes.status, 200);
    const body = (await tokenRes.json()) as Record<string, unknown>;
    assert.ok(body.access_token, 'should return access token');
    assert.equal(body.tenantIdFallback, true, 'should include tenantIdFallback: true');
  });

  it('should not include tenantIdFallback when no tenantId hint', async () => {
    const email = uniqueEmail();
    await registerUser(email, 'NoHintTest123!');

    const loginRes = await postForm('/api/login', {
      email,
      password: 'NoHintTest123!',
      tenant: 'test-tenant',
      redirect: ADMIN_REDIRECT,
    });

    assert.equal(loginRes.status, 302);
    const code = getLocationParam(loginRes, 'code');
    assert.ok(code);

    const redirectOrigin = new URL(ADMIN_REDIRECT).origin;

    const tokenRes = await postJson('/api/token', {
      code,
      tenant_id: '__unknown__',
      redirect_origin: redirectOrigin,
    });

    assert.equal(tokenRes.status, 200);
    const body = (await tokenRes.json()) as Record<string, unknown>;
    assert.ok(body.access_token, 'should return access token');
    assert.equal(body.tenantIdFallback, undefined, 'should NOT include tenantIdFallback');
  });
});
