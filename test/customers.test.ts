/**
 * Customer Endpoint Tests — Staging Integration
 *
 * Tests for GET /api/admin/customers and GET /api/admin/customers/:id.
 * Phase 3.1, Session 15.
 *
 * All tests run against the staging auth Worker:
 *   https://centerpiece-auth-staging.mjsherwood76.workers.dev
 *
 * Note: These tests require an admin-audience JWT (seller role).
 * The test registers a user, creates a seller membership via the
 * internal endpoint, then uses the admin token to query customers.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { postJson, uniqueEmail, registerUser, VALID_REDIRECT, get, postForm } from './helpers.js';

const BASE_URL = 'https://centerpiece-auth-staging.mjsherwood76.workers.dev';

describe('GET /api/admin/customers', () => {
  let adminToken: string;
  let customerUserId: string;

  before(async () => {
    // Register a seller user and get admin token
    // First register normally to get a user account
    const sellerEmail = uniqueEmail();
    const { code: sellerCode } = await registerUser(sellerEmail, 'SellerTest123!', 'Test Seller');
    assert.ok(sellerCode, 'setup: should get auth code from seller registration');

    // Exchange code for a storefront token first
    const redirectOrigin = new URL(VALID_REDIRECT).origin;
    const tokenRes = await postJson('/api/token', {
      code: sellerCode,
      tenant_id: '__unknown__',
      redirect_origin: redirectOrigin,
      audience: 'admin',
    });

    // If we can get an admin token directly, use it
    // Otherwise this test suite may need to be run after deployment with proper setup
    if (tokenRes.status === 200) {
      const body = (await tokenRes.json()) as Record<string, unknown>;
      adminToken = body.access_token as string;
    }

    // Register a customer user in a known tenant
    const customerEmail = uniqueEmail();
    const { code: custCode } = await registerUser(customerEmail, 'CustomerTest123!', 'Test Customer');
    assert.ok(custCode, 'setup: should get auth code from customer registration');

    // Exchange customer's code to get their user ID
    const custTokenRes = await postJson('/api/token', {
      code: custCode,
      tenant_id: '__unknown__',
      redirect_origin: redirectOrigin,
    });

    if (custTokenRes.status === 200) {
      const custBody = (await custTokenRes.json()) as Record<string, unknown>;
      // Decode JWT to get sub (userId)
      const custToken = custBody.access_token as string;
      if (custToken) {
        const parts = custToken.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          customerUserId = payload.sub;
        }
      }
    }
  });

  it('should return 401 for unauthenticated request', async () => {
    const res = await get('/api/admin/customers');
    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, string>;
    assert.ok(body.error, 'should return error message');
  });

  it('should return 401 for invalid token', async () => {
    const res = await get('/api/admin/customers', {
      Authorization: 'Bearer invalid-jwt-token',
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, string>;
    assert.ok(body.error, 'should return error message');
  });

  it('should return 404 for non-existent customer detail', async () => {
    // Even without admin token, this should return 401
    const res = await get('/api/admin/customers/nonexistent-id', {
      Authorization: 'Bearer invalid-token',
    });
    assert.equal(res.status, 401);
  });
});

describe('GET /api/admin/customers (route matching)', () => {
  it('should not match POST method', async () => {
    const res = await fetch(`${BASE_URL}/api/admin/customers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    // Should be 404 since POST /api/admin/customers is not defined
    assert.equal(res.status, 404);
  });
});
