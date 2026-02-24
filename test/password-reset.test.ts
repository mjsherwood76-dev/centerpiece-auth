/**
 * Password Reset Flow Tests — Staging Integration
 *
 * Tests the forgot-password → reset-password flow.
 *
 * NOTE: Since we can't receive emails in tests, we test:
 * 1. forgot-password always returns success (account enumeration prevention)
 * 2. reset-password rejects invalid/expired/missing tokens
 * 3. The Worker logs the reset URL (which we can check via `wrangler tail`)
 *
 * Full e2e test of the reset flow (with real token) would require
 * either D1 direct access or a test-only endpoint to retrieve the token.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { postForm, uniqueEmail, getLocationParam, registerUser, BASE_URL } from './helpers.js';

describe('POST /api/forgot-password', () => {
  it('should redirect with reset_sent for existing email (no leak)', async () => {
    const email = uniqueEmail();
    await registerUser(email, 'ForgotTestPass123!');

    const res = await postForm('/api/forgot-password', {
      email,
      tenant: 'test-tenant',
    });

    assert.equal(res.status, 302, 'should redirect');
    const location = res.headers.get('Location') || '';
    assert.ok(location.includes('message=reset_sent'), 'should include reset_sent message');
  });

  it('should redirect with reset_sent for NON-existing email (account enumeration prevention)', async () => {
    const res = await postForm('/api/forgot-password', {
      email: 'does-not-exist-xyz@nowhere.com',
      tenant: 'test-tenant',
    });

    assert.equal(res.status, 302, 'should redirect');
    const location = res.headers.get('Location') || '';
    assert.ok(location.includes('message=reset_sent'), 'should return same success for non-existent email');
  });

  it('should redirect with reset_sent even for empty email', async () => {
    const res = await postForm('/api/forgot-password', {
      email: '',
      tenant: 'test-tenant',
    });

    assert.equal(res.status, 302);
    const location = res.headers.get('Location') || '';
    assert.ok(location.includes('message=reset_sent'));
  });
});

describe('POST /api/reset-password', () => {
  it('should reject invalid token', async () => {
    const res = await postForm('/api/reset-password', {
      token: 'completely-invalid-token',
      newPassword: 'NewSecurePass123!',
      confirmPassword: 'NewSecurePass123!',
      tenant: 'test-tenant',
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_token', 'should report invalid_token');
  });

  it('should reject missing token', async () => {
    const res = await postForm('/api/reset-password', {
      token: '',
      newPassword: 'NewSecurePass123!',
      confirmPassword: 'NewSecurePass123!',
      tenant: 'test-tenant',
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_token');
  });

  it('should reject weak new password', async () => {
    const res = await postForm('/api/reset-password', {
      token: 'some-token-value',
      newPassword: 'short',
      confirmPassword: 'short',
      tenant: 'test-tenant',
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'password_weak');
  });

  it('should reject password mismatch', async () => {
    const res = await postForm('/api/reset-password', {
      token: 'some-token-value',
      newPassword: 'NewSecurePass123!',
      confirmPassword: 'DifferentPass123!',
      tenant: 'test-tenant',
    });

    assert.equal(res.status, 302);
    const error = getLocationParam(res, 'error');
    assert.equal(error, 'password_mismatch');
  });
});
