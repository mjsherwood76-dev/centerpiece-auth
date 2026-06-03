/**
 * Renderer Unit Tests
 *
 * Tests for renderAuthPage() in src/pages/renderer.ts.
 * Pure unit tests — no network, no KV, no D1.
 * Covers: backLink rendering, legal footer cluster, platform-domain consumption.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { renderAuthPage } from '../src/pages/renderer.js';
import type { TenantBranding } from '../src/branding.js';

// ─── Fixture ────────────────────────────────────────────────

function makeBranding(overrides: Partial<TenantBranding> = {}): TenantBranding {
  return {
    tenantId: 'test-tenant',
    storeName: 'Test Store',
    logoUrl: null,
    cssVariables: ':root { --foreground: 222 47% 11%; }',
    googleFontsLinks: '',
    ...overrides,
  };
}

const CONTENT = { title: 'Sign In', body: '<form id="test-form"></form>' };

// ─── Back-link tests ─────────────────────────────────────────

describe('renderAuthPage — backLink', () => {
  it('renders without backLink — no .auth-header__back anchor element', () => {
    const html = renderAuthPage(makeBranding(), CONTENT, 'centerpiecelab.com');
    // CSS defines .auth-header__back styles; check that no <a> with that class is rendered
    assert.ok(!html.includes('<a href=') || !html.includes('auth-header__back"'), 'back link anchor should be absent when not supplied');
    // More precise: the back-link element uses class="auth-header__back" only when rendered
    assert.ok(!html.includes('class="auth-header__back"'), 'auth-header__back anchor should not be rendered without backLink param');
  });

  it('renders with backLink — contains href and label', () => {
    const html = renderAuthPage(makeBranding(), CONTENT, 'centerpiecelab.com', {
      href: 'https://test-store.centerpiece.shop',
      label: 'Back to Test Store',
    });
    assert.ok(html.includes('auth-header__back'), 'should render back link element');
    assert.ok(html.includes('https://test-store.centerpiece.shop'), 'should include back-link href');
    assert.ok(html.includes('Back to Test Store'), 'should include back-link label');
  });

  it('escapes backLink label to prevent XSS', () => {
    const html = renderAuthPage(makeBranding(), CONTENT, 'centerpiecelab.com', {
      href: 'https://test-store.centerpiece.shop',
      label: '<script>alert(1)</script>',
    });
    assert.ok(!html.includes('<script>alert(1)</script>'), 'raw script tag should not appear');
    assert.ok(html.includes('&lt;script&gt;'), 'label should be HTML-escaped');
  });

  it('escapes backLink href attribute to prevent XSS', () => {
    const html = renderAuthPage(makeBranding(), CONTENT, 'centerpiecelab.com', {
      href: 'https://safe.centerpiece.shop?a="b',
      label: 'Back',
    });
    // The href in the attribute should be escaped (double-quote replaced with &quot;)
    assert.ok(!html.includes('href="https://safe.centerpiece.shop?a="b"'), 'raw double-quote should not appear unescaped in href');
  });
});

// ─── Legal footer tests ──────────────────────────────────────

describe('renderAuthPage — legal footer cluster', () => {
  it('footer contains .auth-footer__legal with Privacy, Terms, Cookies anchors', () => {
    const html = renderAuthPage(makeBranding(), CONTENT, 'centerpiecelab.com');
    assert.ok(html.includes('auth-footer__legal'), 'should render legal footer cluster');
    assert.ok(html.includes('/policies/privacy'), 'should link to privacy policy');
    assert.ok(html.includes('/policies/terms'), 'should link to terms');
    assert.ok(html.includes('/policies/cookies'), 'should link to cookies policy');
    assert.ok(html.includes('>Privacy<'), 'should have Privacy anchor text');
    assert.ok(html.includes('>Terms<'), 'should have Terms anchor text');
    assert.ok(html.includes('>Cookies<'), 'should have Cookies anchor text');
  });

  it('footer copyright contains storeName', () => {
    const html = renderAuthPage(makeBranding({ storeName: 'My Shop' }), CONTENT, 'centerpiecelab.com');
    assert.ok(html.includes('auth-footer__copyright'), 'should render copyright element');
    assert.ok(html.includes('My Shop'), 'copyright should include storeName');
  });

  it('uses production platformDomain in footer links', () => {
    const html = renderAuthPage(makeBranding(), CONTENT, 'centerpiecelab.com');
    assert.ok(html.includes('https://centerpiecelab.com/policies/privacy'), 'prod privacy link correct');
    assert.ok(html.includes('https://centerpiecelab.com/policies/terms'), 'prod terms link correct');
    assert.ok(html.includes('https://centerpiecelab.com/policies/cookies'), 'prod cookies link correct');
  });

  it('uses staging platformDomain in footer links', () => {
    const html = renderAuthPage(makeBranding(), CONTENT, 'centerpiecelab.dev');
    assert.ok(html.includes('https://centerpiecelab.dev/policies/privacy'), 'staging privacy link correct');
    assert.ok(html.includes('https://centerpiecelab.dev/policies/terms'), 'staging terms link correct');
    assert.ok(html.includes('https://centerpiecelab.dev/policies/cookies'), 'staging cookies link correct');
  });
});

// ─── Page title test ─────────────────────────────────────────

describe('renderAuthPage — page title', () => {
  it('<title> uses storeName', () => {
    const html = renderAuthPage(makeBranding({ storeName: 'Acme Corp' }), CONTENT, 'centerpiecelab.com');
    assert.ok(html.includes('Acme Corp'), 'title should include storeName');
    assert.ok(html.includes('<title>'), 'should have title element');
  });
});
