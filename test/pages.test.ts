/**
 * Pages Tests — Staging Integration
 *
 * Tests that login, register, and reset-password pages render correctly.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { get } from './helpers.js';

describe('GET /login', () => {
  it('should render login page with tenant branding fields', async () => {
    const res = await get('/login?tenant=test-tenant&redirect=https://test.centerpiece.shop/shop');
    assert.equal(res.status, 200);
    const ct = res.headers.get('Content-Type') || '';
    assert.ok(ct.includes('text/html'), 'should be HTML');
    const html = await res.text();
    assert.ok(html.includes('form'), 'should contain a form');
    assert.ok(html.includes('email'), 'should have email field');
    assert.ok(html.includes('password'), 'should have password field');
  });

  it('should include the tenant param in hidden fields', async () => {
    const res = await get('/login?tenant=my-store&redirect=https://test.centerpiece.shop/shop');
    const html = await res.text();
    assert.ok(html.includes('my-store'), 'tenant should appear in form');
  });

  it('should show success message for reset_sent', async () => {
    const res = await get('/login?tenant=test&redirect=https://test.centerpiece.shop/shop&message=reset_sent');
    const html = await res.text();
    // The page should show a success message for password reset email sent
    assert.ok(
      html.includes('reset') || html.includes('sent') || html.includes('success') || html.includes('auth-success'),
      'should show reset_sent message'
    );
  });

  it('should show success message for password_changed', async () => {
    const res = await get('/login?tenant=test&redirect=https://test.centerpiece.shop/shop&message=password_changed');
    const html = await res.text();
    assert.ok(
      html.includes('changed') || html.includes('success') || html.includes('auth-success'),
      'should show password_changed message'
    );
  });
});

describe('GET /register', () => {
  it('should render register page as HTML', async () => {
    const res = await get('/register?tenant=test-tenant&redirect=https://test.centerpiece.shop/shop');
    assert.equal(res.status, 200);
    const ct = res.headers.get('Content-Type') || '';
    assert.ok(ct.includes('text/html'));
    const html = await res.text();
    assert.ok(html.includes('form'), 'should contain a form');
    assert.ok(html.includes('email'), 'should have email field');
    assert.ok(html.includes('password'), 'should have password field');
    assert.ok(html.includes('name') || html.includes('Name'), 'should have name field');
  });
});

describe('GET /reset-password', () => {
  it('should render forgot-password form when no token provided', async () => {
    const res = await get('/reset-password?tenant=test-tenant');
    assert.equal(res.status, 200);
    const ct = res.headers.get('Content-Type') || '';
    assert.ok(ct.includes('text/html'));
    const html = await res.text();
    assert.ok(html.includes('email'), 'should have email field for forgot password');
  });

  it('should render new-password form when token is provided', async () => {
    const res = await get('/reset-password?tenant=test-tenant&token=fake-token-12345');
    assert.equal(res.status, 200);
    const html = await res.text();
    // When a token is present, should show new password fields
    assert.ok(
      html.includes('newPassword') || html.includes('new-password') || html.includes('New'),
      'should have new password field'
    );
  });
});
