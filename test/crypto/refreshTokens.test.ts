/**
 * Unit tests for refreshTokens.ts cookie header builders.
 *
 * Pure unit tests — no network, no D1, no Worker required.
 * Tests the SameSite=None; Partitioned cookie attribute flip introduced in
 * Fix_Auth_Session_UX S1 (previously SameSite=Lax, broken for iframe subresource requests).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildRefreshCookieHeader,
  buildClearRefreshCookieHeader,
} from '../../src/crypto/refreshTokens.js';

// ─── buildRefreshCookieHeader ────────────────────────────────

describe('buildRefreshCookieHeader', () => {
  const AUTH_DOMAIN_PROD = 'https://auth.centerpiecelab.com';
  const AUTH_DOMAIN_STAGING = 'https://auth.centerpiecelab.dev';
  const AUTH_DOMAIN_LOCAL = 'http://localhost:8788';

  it('contains SameSite=None on production domain', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('SameSite=None'), `Expected SameSite=None in: ${cookie}`);
  });

  it('contains Secure on production domain', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('Secure'), `Expected Secure in: ${cookie}`);
  });

  it('contains Partitioned on production domain', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('Partitioned'), `Expected Partitioned in: ${cookie}`);
  });

  it('does NOT contain SameSite=Lax on production domain', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_PROD);
    assert.ok(!cookie.includes('SameSite=Lax'), `Unexpected SameSite=Lax in: ${cookie}`);
  });

  it('contains correct Domain on production domain', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('Domain=auth.centerpiecelab.com'), `Expected Domain=auth.centerpiecelab.com in: ${cookie}`);
  });

  it('contains correct Max-Age for 30 days', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_PROD);
    const expectedMaxAge = 30 * 24 * 60 * 60; // 2592000
    assert.ok(cookie.includes(`Max-Age=${expectedMaxAge}`), `Expected Max-Age=${expectedMaxAge} in: ${cookie}`);
  });

  it('contains correct Max-Age for 90 days', () => {
    const cookie = buildRefreshCookieHeader('token123', 90, AUTH_DOMAIN_PROD);
    const expectedMaxAge = 90 * 24 * 60 * 60; // 7776000
    assert.ok(cookie.includes(`Max-Age=${expectedMaxAge}`), `Expected Max-Age=${expectedMaxAge} in: ${cookie}`);
  });

  it('contains HttpOnly', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('HttpOnly'), `Expected HttpOnly in: ${cookie}`);
  });

  it('contains Path=/', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('Path=/'), `Expected Path=/ in: ${cookie}`);
  });

  it('includes the token value', () => {
    const token = 'abc123xyz';
    const cookie = buildRefreshCookieHeader(token, 30, AUTH_DOMAIN_PROD);
    assert.ok(cookie.startsWith(`cp_refresh=${token}`), `Expected cp_refresh=${token} at start of: ${cookie}`);
  });

  it('works the same for staging domain (.dev)', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_STAGING);
    assert.ok(cookie.includes('SameSite=None'), 'staging: SameSite=None expected');
    assert.ok(cookie.includes('Secure'), 'staging: Secure expected');
    assert.ok(cookie.includes('Partitioned'), 'staging: Partitioned expected');
    assert.ok(cookie.includes('Domain=auth.centerpiecelab.dev'), 'staging: correct Domain expected');
  });

  it('uses SameSite=Lax without Secure or Partitioned on localhost', () => {
    const cookie = buildRefreshCookieHeader('token123', 30, AUTH_DOMAIN_LOCAL);
    assert.ok(cookie.includes('SameSite=Lax'), `Expected SameSite=Lax on localhost in: ${cookie}`);
    assert.ok(!cookie.includes('Secure'), `Unexpected Secure on localhost in: ${cookie}`);
    assert.ok(!cookie.includes('Partitioned'), `Unexpected Partitioned on localhost in: ${cookie}`);
    assert.ok(!cookie.includes('Domain='), `Unexpected Domain= on localhost in: ${cookie}`);
  });
});

// ─── buildClearRefreshCookieHeader ──────────────────────────

describe('buildClearRefreshCookieHeader', () => {
  const AUTH_DOMAIN_PROD = 'https://auth.centerpiecelab.com';
  const AUTH_DOMAIN_LOCAL = 'http://localhost:8788';

  it('contains SameSite=None on production domain (must mirror set-cookie attributes)', () => {
    const cookie = buildClearRefreshCookieHeader(AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('SameSite=None'), `Expected SameSite=None in: ${cookie}`);
  });

  it('contains Secure on production domain', () => {
    const cookie = buildClearRefreshCookieHeader(AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('Secure'), `Expected Secure in: ${cookie}`);
  });

  it('contains Partitioned on production domain', () => {
    const cookie = buildClearRefreshCookieHeader(AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('Partitioned'), `Expected Partitioned in: ${cookie}`);
  });

  it('has Max-Age=0 (deletion)', () => {
    const cookie = buildClearRefreshCookieHeader(AUTH_DOMAIN_PROD);
    assert.ok(cookie.includes('Max-Age=0'), `Expected Max-Age=0 in: ${cookie}`);
  });

  it('uses SameSite=Lax without Secure or Partitioned on localhost', () => {
    const cookie = buildClearRefreshCookieHeader(AUTH_DOMAIN_LOCAL);
    assert.ok(cookie.includes('SameSite=Lax'), `Expected SameSite=Lax on localhost in: ${cookie}`);
    assert.ok(!cookie.includes('Secure'), `Unexpected Secure on localhost in: ${cookie}`);
    assert.ok(!cookie.includes('Partitioned'), `Unexpected Partitioned on localhost in: ${cookie}`);
  });
});
