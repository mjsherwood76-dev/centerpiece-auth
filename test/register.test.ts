/**
 * Registration Flow Tests — Staging Integration
 *
 * Tests POST /api/register against real staging D1.
 * Each test uses a unique email (uniqueEmail()) for isolation.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { postForm, uniqueEmail, VALID_REDIRECT, getLocationParam, registerUser } from './helpers.js';

describe('POST /api/register', () => {
  it('should register a new user and redirect with auth code', async () => {
    const email = uniqueEmail();
    const { response, code, refreshCookie } = await registerUser(email, 'SecurePass123!');

    assert.equal(response.status, 302, 'should redirect');
    const location = response.headers.get('Location') || '';
    assert.ok(location.includes('/auth/callback'), 'should redirect to /auth/callback');
    assert.ok(code, 'should have an authorization code');
    assert.ok(refreshCookie, 'should set a refresh token cookie');
    assert.ok(refreshCookie!.includes('HttpOnly'), 'cookie should be HttpOnly');
    assert.ok(refreshCookie!.includes('Secure'), 'cookie should be Secure');
  });

  it('should reject duplicate email registration', async () => {
    const email = uniqueEmail();
    // Register first time
    await registerUser(email, 'SecurePass123!');

    // Attempt duplicate
    const res = await postForm('/api/register', {
      email,
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Duplicate User',
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'email_exists', 'should report email_exists error');
  });

  it('should reject weak password (less than 8 chars)', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'short',
      confirmPassword: 'short',
      name: 'Test User',
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'password_weak');
  });

  it('should reject password mismatch', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'DifferentPass!',
      name: 'Test User',
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'password_mismatch');
  });

  it('should reject invalid email format', async () => {
    const res = await postForm('/api/register', {
      email: 'not-an-email',
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test User',
      tenant: 'test-tenant',
      redirect: VALID_REDIRECT,
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_email');
  });

  it('should reject invalid redirect URL', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test User',
      tenant: 'test-tenant',
      redirect: 'https://evil.com/steal',
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });

  it('should reject missing redirect URL', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test User',
      tenant: 'test-tenant',
      redirect: '',
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });
});
