/**
 * Redirect Validation Tests — Staging Integration
 *
 * Tests that the redirect URL validation in register/login
 * correctly rejects dangerous URLs (IP literals, javascript:, unknown domains).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { postForm, uniqueEmail, getLocationParam } from './helpers.js';

describe('Redirect URL validation', () => {
  it('should accept *.centerpiece.shop', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test',
      tenant: 'test',
      redirect: 'https://mystore.centerpiece.shop/shop',
    });

    // Should NOT be invalid_redirect (may be another error or success)
    const error = getLocationParam(res, 'error');
    assert.notEqual(error, 'invalid_redirect', 'should accept .centerpiece.shop');
  });

  it('should accept *.centerpiece.app', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test',
      tenant: 'test',
      redirect: 'https://mystore.centerpiece.app/',
    });

    const error = getLocationParam(res, 'error');
    assert.notEqual(error, 'invalid_redirect', 'should accept .centerpiece.app');
  });

  it('should accept *.workers.dev (staging)', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test',
      tenant: 'test',
      redirect: 'https://mysite.workers.dev/',
    });

    const error = getLocationParam(res, 'error');
    assert.notEqual(error, 'invalid_redirect', 'should accept .workers.dev');
  });

  it('should reject unknown domain', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test',
      tenant: 'test',
      redirect: 'https://unknown-domain.com/callback',
    });

    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });

  it('should reject javascript: URI', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test',
      tenant: 'test',
      redirect: 'javascript:alert(1)',
    });

    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });

  it('should reject IP literal redirect', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test',
      tenant: 'test',
      redirect: 'https://192.168.1.1/callback',
    });

    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });

  it('should reject http: on non-localhost', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test',
      tenant: 'test',
      redirect: 'http://mystore.centerpiece.shop/shop',
    });

    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });

  it('should reject URLs with fragments', async () => {
    const res = await postForm('/api/register', {
      email: uniqueEmail(),
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      name: 'Test',
      tenant: 'test',
      redirect: 'https://mystore.centerpiece.shop/shop#fragment',
    });

    const error = getLocationParam(res, 'error');
    assert.equal(error, 'invalid_redirect');
  });
});
