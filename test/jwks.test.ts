/**
 * JWKS Endpoint Tests — Staging Integration
 *
 * Tests /.well-known/jwks.json returns a valid JWKS with the correct key.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { get } from './helpers.js';

describe('GET /.well-known/jwks.json', () => {
  it('should return a valid JWKS with ES256 key', async () => {
    const res = await get('/.well-known/jwks.json');
    assert.equal(res.status, 200);

    const ct = res.headers.get('Content-Type') || '';
    assert.ok(ct.includes('application/json'));

    const body = (await res.json()) as { keys: Array<Record<string, string>> };
    assert.ok(Array.isArray(body.keys), 'should have keys array');
    assert.ok(body.keys.length >= 1, 'should have at least one key');

    const key = body.keys[0];
    assert.equal(key.kty, 'EC', 'key type should be EC');
    assert.equal(key.crv, 'P-256', 'curve should be P-256');
    assert.equal(key.alg, 'ES256', 'algorithm should be ES256');
    assert.equal(key.use, 'sig', 'use should be sig');
    assert.ok(key.kid, 'should have a key ID');
    assert.ok(key.x, 'should have x coordinate');
    assert.ok(key.y, 'should have y coordinate');
  });

  it('should be cacheable', async () => {
    const res = await get('/.well-known/jwks.json');
    const cc = res.headers.get('Cache-Control') || '';
    assert.ok(cc.includes('max-age'), 'should have max-age cache control');
  });
});
