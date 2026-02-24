/**
 * Health & Security Headers Tests
 *
 * Tests against staging:
 * - /health returns valid JSON
 * - Security headers present on all responses
 * - CORS preflight behavior
 * - 404 for unknown routes
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { BASE_URL, get } from './helpers.js';

describe('GET /health', () => {
  it('should return 200 with OK status', async () => {
    const res = await get('/health');
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.status, 'ok');
    assert.equal(body.service, 'centerpiece-auth');
    assert.equal(body.environment, 'staging');
    assert.ok(body.timestamp, 'should have a timestamp');
  });
});

describe('Security headers', () => {
  it('should include X-Frame-Options: DENY on JSON endpoints', async () => {
    const res = await get('/health');
    assert.equal(res.headers.get('X-Frame-Options'), 'DENY');
  });

  it('should include X-Content-Type-Options: nosniff', async () => {
    const res = await get('/health');
    assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff');
  });

  it('should include Referrer-Policy', async () => {
    const res = await get('/health');
    assert.equal(res.headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin');
  });

  it('should include Permissions-Policy', async () => {
    const res = await get('/health');
    const pp = res.headers.get('Permissions-Policy');
    assert.ok(pp, 'should have Permissions-Policy');
    assert.ok(pp!.includes('camera=()'), 'should restrict camera');
  });

  it('should include CSP on HTML pages', async () => {
    const res = await get('/login?tenant=test&redirect=https://test.centerpiece.shop/shop');
    const csp = res.headers.get('Content-Security-Policy');
    assert.ok(csp, 'HTML pages should have CSP');
    assert.ok(csp!.includes("frame-ancestors 'none'"), 'CSP should block framing');
  });
});

describe('CORS preflight', () => {
  it('should allow OPTIONS from controlled origins', async () => {
    const res = await fetch(`${BASE_URL}/api/token`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://test-store.centerpiece.shop',
        'Access-Control-Request-Method': 'POST',
      },
    });
    assert.equal(res.status, 204);
    assert.equal(res.headers.get('Access-Control-Allow-Origin'), 'https://test-store.centerpiece.shop');
    assert.equal(res.headers.get('Access-Control-Allow-Credentials'), 'true');
  });

  it('should NOT set Allow-Origin for unknown origins', async () => {
    const res = await fetch(`${BASE_URL}/api/token`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil.com',
        'Access-Control-Request-Method': 'POST',
      },
    });
    assert.equal(res.status, 204);
    const allowOrigin = res.headers.get('Access-Control-Allow-Origin');
    assert.ok(!allowOrigin, 'should NOT allow evil.com');
  });
});

describe('404 handling', () => {
  it('should return 404 JSON for unknown routes', async () => {
    const res = await get('/nonexistent-route');
    assert.equal(res.status, 404);
    const body = (await res.json()) as Record<string, string>;
    assert.equal(body.error, 'Not found');
  });

  it('should include security headers on 404', async () => {
    const res = await get('/nonexistent-route');
    assert.equal(res.headers.get('X-Frame-Options'), 'DENY');
  });
});
