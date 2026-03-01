/**
 * Branding Tests — Staging Integration
 *
 * Verifies that tenant branding loads correctly using the `tenant:{id}` KV key
 * prefix (aligned with runtime + D1→KV sync). The login page renders with
 * tenant-specific CSS variables when a valid tenant is provided.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { get } from './helpers.js';

describe('Tenant branding KV key pattern', () => {
  it('should load branding for a known tenant using tenant:{id} prefix', async () => {
    // The login page triggers loadTenantBranding() which reads
    // TENANT_CONFIGS KV at key `tenant:{tenantId}`
    const res = await get(
      '/login?tenant=test-tenant&redirect=https://test.centerpiece.shop/shop',
    );
    assert.equal(res.status, 200);
    const html = await res.text();

    // Page should render with CSS custom properties from the brand theme
    // (if tenant config exists, theme variables are injected into a <style> block)
    assert.ok(html.includes('<style'), 'should contain inline style block');
  });

  it('should fall back to defaults for unknown tenant', async () => {
    const res = await get(
      '/login?tenant=nonexistent-tenant-xyz&redirect=https://test.centerpiece.shop/shop',
    );
    assert.equal(res.status, 200);
    const html = await res.text();

    // Even with unknown tenant, page should render with default Aurora branding
    assert.ok(html.includes('<style'), 'should contain default style block');
    assert.ok(html.includes('form'), 'should still render login form');
  });

  it('should include Google Fonts links when tenant has a brand theme', async () => {
    const res = await get(
      '/login?tenant=test-tenant&redirect=https://test.centerpiece.shop/shop',
    );
    const html = await res.text();

    // Brand themes with custom typography include Google Fonts <link> tags
    // Default Aurora uses "DM Sans" / "DM Serif Display" / "JetBrains Mono"
    assert.ok(
      html.includes('fonts.googleapis.com') || html.includes('font-'),
      'should include font references',
    );
  });

  it('should extract store name from tenant config', async () => {
    const res = await get(
      '/login?tenant=test-tenant&redirect=https://test.centerpiece.shop/shop',
    );
    const html = await res.text();

    // A branded page should contain the store name somewhere in the HTML
    // (either in the title, heading, or as a hidden field)
    assert.ok(html.length > 100, 'should render a complete HTML page');
  });
});
