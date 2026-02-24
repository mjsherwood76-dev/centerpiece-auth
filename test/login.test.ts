/**
 * Login Flow Tests — Staging Integration
 *
 * Tests POST /api/login against real staging D1.
 * Registers a user first, then tests login success/failure.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { postForm, uniqueEmail, VALID_REDIRECT, getLocationParam, registerUser } from './helpers.js';

describe('POST /api/login', () => {
  let testEmail: string;
  const testPassword = 'LoginTestPass123!';

  before(async () => {
    // Register a user for login tests
    testEmail = uniqueEmail();
    await registerUser(testEmail, testPassword);
  });

  it('should login successfully with correct credentials', async () => {
    const res = await postForm('/api/login', {
      email: testEmail,
      password: testPassword,
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
    });

    assert.equal(res.status, 302, 'should redirect');
    const location = res.headers.get('Location') || '';
    assert.ok(location.includes('/auth/callback'), 'should redirect to /auth/callback');
    const code = getLocationParam(res, 'code');
    assert.ok(code, 'should include an authorization code');
    const cookie = res.headers.get('Set-Cookie');
    assert.ok(cookie, 'should set refresh token cookie');
  });

  it('should reject wrong password with generic error', async () => {
    const res = await postForm('/api/login', {
      email: testEmail,
      password: 'WrongPassword123!',
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_credentials', 'should return generic invalid_credentials');
  });

  it('should reject non-existent user with same generic error', async () => {
    const res = await postForm('/api/login', {
      email: 'nonexistent-user-xyz@example.com',
      password: 'AnyPassword123!',
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_credentials', 'should return same generic error for non-existent user');
  });

  it('should reject missing redirect URL', async () => {
    const res = await postForm('/api/login', {
      email: testEmail,
      password: testPassword,
      tenant: 'test-tenant',
      redirect: '',
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });

  it('should reject invalid redirect domain', async () => {
    const res = await postForm('/api/login', {
      email: testEmail,
      password: testPassword,
      tenant: 'test-tenant',
      redirect: 'https://evil.com/steal',
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });
});
