/**
 * Memberships Endpoint Tests — Staging Integration
 *
 * Tests GET /api/memberships endpoint (Phase 2.3 Session 1).
 *
 * All tests run against the staging auth Worker:
 *   https://centerpiece-auth-staging.mjsherwood76.workers.dev
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { postJson, uniqueEmail, registerUser, VALID_REDIRECT, get } from './helpers.js';

describe('GET /api/memberships', () => {
  let accessToken: string;

  before(async () => {
    // Register a user and exchange code for JWT
    const email = uniqueEmail();
    const { code } = await registerUser(email, 'MembershipTest123!');
    assert.ok(code, 'setup: should get auth code from registration');

    const redirectOrigin = new URL(VALID_REDIRECT).origin;
    const tenantId = '__unknown__';

    const tokenRes = await postJson('/api/token', {
      code,
      tenant_id: tenantId,
      redirect_origin: redirectOrigin,
    });

    assert.equal(tokenRes.status, 200, 'setup: token exchange should succeed');
    const body = (await tokenRes.json()) as Record<string, unknown>;
    accessToken = body.access_token as string;
    assert.ok(accessToken, 'setup: should have access token');
  });

  it('should return memberships for authenticated user', async () => {
    const res = await get('/api/memberships', {
      Authorization: `Bearer ${accessToken}`,
    });

    assert.equal(res.status, 200);
    const body = (await res.json()) as { memberships: Array<{ tenantId: string; role: string; status: string }> };
    assert.ok(Array.isArray(body.memberships), 'should return memberships array');
    // The user was registered with a redirect to *.centerpiece.shop, so they should have
    // at least one membership with role 'customer'
    assert.ok(body.memberships.length >= 1, 'should have at least one membership');
    const customerMembership = body.memberships.find(m => m.role === 'customer');
    assert.ok(customerMembership, 'should have a customer membership');
    assert.equal(customerMembership!.status, 'active', 'membership should be active');
  });

  it('should return 401 for unauthenticated request', async () => {
    const res = await get('/api/memberships');

    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, string>;
    assert.ok(body.error, 'should return error message');
  });

  it('should return 401 for invalid token', async () => {
    const res = await get('/api/memberships', {
      Authorization: 'Bearer totally-invalid-jwt-token',
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, string>;
    assert.ok(body.error, 'should return error message');
  });
});
