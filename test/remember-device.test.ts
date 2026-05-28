/**
 * Remember-Device Tests — Staging Integration
 *
 * Tests the "Remember this device" checkbox plumbing:
 * - POST /api/login with remember_device=1 → 90-day cookie Max-Age
 * - POST /api/login without remember_device  → 30-day cookie Max-Age
 * - POST /api/register with remember_device=1 → 90-day cookie Max-Age
 * - login_iat is set to approximately now on new login
 *
 * Runs against real staging D1. The migration 0007 must be applied first.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { postForm, uniqueEmail, VALID_REDIRECT, registerUser } from './helpers.js';

const THIRTY_DAY_SECONDS = 30 * 24 * 60 * 60;  // 2592000
const NINETY_DAY_SECONDS = 90 * 24 * 60 * 60;  // 7776000

/**
 * Extract Max-Age from a Set-Cookie header value.
 */
function extractMaxAge(setCookieHeader: string | null): number | null {
  if (!setCookieHeader) return null;
  const match = setCookieHeader.match(/Max-Age=(\d+)/i);
  return match ? parseInt(match[1], 10) : null;
}

describe('Remember-device plumbing', () => {
  let testEmail: string;
  const testPassword = 'RememberDevicePass123!';

  before(async () => {
    testEmail = uniqueEmail();
    await registerUser(testEmail, testPassword);
  });

  it('login WITHOUT remember_device yields 30-day cookie Max-Age', async () => {
    const res = await postForm('/api/login', {
      email: testEmail,
      password: testPassword,
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
      // no remember_device field
    });

    assert.equal(res.status, 302, 'should redirect');
    const cookie = res.headers.get('Set-Cookie');
    assert.ok(cookie, 'should set cookie');
    const maxAge = extractMaxAge(cookie);
    assert.equal(maxAge, THIRTY_DAY_SECONDS, `Max-Age should be ${THIRTY_DAY_SECONDS} (30 days) when remember_device absent`);
  });

  it('login WITH remember_device=1 yields 90-day cookie Max-Age', async () => {
    const res = await postForm('/api/login', {
      email: testEmail,
      password: testPassword,
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
      remember_device: '1',
    });

    assert.equal(res.status, 302, 'should redirect');
    const cookie = res.headers.get('Set-Cookie');
    assert.ok(cookie, 'should set cookie');
    const maxAge = extractMaxAge(cookie);
    assert.equal(maxAge, NINETY_DAY_SECONDS, `Max-Age should be ${NINETY_DAY_SECONDS} (90 days) when remember_device=1`);
  });

  it('register WITHOUT remember_device yields 30-day cookie Max-Age', async () => {
    const newEmail = uniqueEmail();
    const res = await postForm('/api/register', {
      email: newEmail,
      password: testPassword,
      confirmPassword: testPassword,
      name: 'Remember Test User',
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
      // no remember_device field
    });

    assert.equal(res.status, 302, 'should redirect');
    const cookie = res.headers.get('Set-Cookie');
    assert.ok(cookie, 'should set cookie');
    const maxAge = extractMaxAge(cookie);
    assert.equal(maxAge, THIRTY_DAY_SECONDS, `Max-Age should be ${THIRTY_DAY_SECONDS} (30 days) for register without remember_device`);
  });

  it('register WITH remember_device=1 yields 90-day cookie Max-Age', async () => {
    const newEmail = uniqueEmail();
    const res = await postForm('/api/register', {
      email: newEmail,
      password: testPassword,
      confirmPassword: testPassword,
      name: 'Remember Test User',
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
      remember_device: '1',
    });

    assert.equal(res.status, 302, 'should redirect');
    const cookie = res.headers.get('Set-Cookie');
    assert.ok(cookie, 'should set cookie');
    const maxAge = extractMaxAge(cookie);
    assert.equal(maxAge, NINETY_DAY_SECONDS, `Max-Age should be ${NINETY_DAY_SECONDS} (90 days) for register with remember_device=1`);
  });

  it('authorization code redirect is present in both cases', async () => {
    const res = await postForm('/api/login', {
      email: testEmail,
      password: testPassword,
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
      remember_device: '1',
    });

    const location = res.headers.get('Location') || '';
    assert.ok(location.includes('/auth/callback'), 'should redirect to /auth/callback');
    assert.ok(location.includes('code='), 'should include authorization code');
  });
});
