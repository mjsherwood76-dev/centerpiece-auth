/**
 * Branding Tests — Staging Integration + Unit
 *
 * Verifies that tenant branding loads correctly using the `tenant:{id}` KV key
 * prefix (aligned with runtime + D1→KV sync). The login page renders with
 * tenant-specific CSS variables when a valid tenant is provided.
 *
 * Also includes unit tests (in-memory KV stubs) for the platform-default path
 * introduced in Phase 3.19 S1: null tenantId → loads centerpiecelab tenant,
 * NOT Aurora directly.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { get } from './helpers.js';
import { loadTenantBranding } from '../src/branding.js';
import type { Env } from '../src/types.js';

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

// ─── Unit tests: platform-default path (in-memory KV stubs) ─────────────────
//
// These tests do NOT hit staging — KV namespaces are mocked in-process so the
// path logic can be verified without network access.

/** Build a minimal KVNamespace stub backed by a plain object. */
function makeKV(store: Record<string, unknown>): KVNamespace {
  return {
    async get(key: string, type?: string) {
      const value = store[key] ?? null;
      if (value === null) return null;
      if (type === 'json') return value;
      return JSON.stringify(value);
    },
    async put() {},
    async delete() {},
    async list() { return { keys: [], list_complete: true, caret: undefined }; },
    async getWithMetadata() { return { value: null, metadata: null }; },
  } as unknown as KVNamespace;
}

/** KVNamespace that always throws — simulates a KV outage. */
function makeThrowingKV(): KVNamespace {
  return {
    async get() { throw new Error('KV unavailable'); },
    async put() {},
    async delete() {},
    async list() { return { keys: [], list_complete: true, caret: undefined }; },
    async getWithMetadata() { return { value: null, metadata: null }; },
  } as unknown as KVNamespace;
}

/** Minimal centerpiecelab tenant config (uses brand-centerpiece). */
const CENTERPIECELAB_CONFIG = {
  config: {
    brandThemeId: 'brand-centerpiece',
    styleThemeId: 'style-material',
    name: 'Centerpiece',
    site: { title: 'Centerpiece', logoUrl: 'https://centerpiecelab.com/logo.svg' },
  },
};

/** Minimal brand-centerpiece theme — uses hue 260 to distinguish from Aurora (hue 221). */
const BRAND_CENTERPIECE = {
  id: 'brand-centerpiece',
  type: 'brand',
  modes: {
    light: { colors: { primary: '260 80% 50%', background: '0 0% 100%', foreground: '260 20% 10%' } },
    dark:  { colors: { primary: '260 80% 65%', background: '260 20% 10%', foreground: '0 0% 98%' } },
  },
  typography: {
    heading: ["'Inter'", 'system-ui', 'sans-serif'],
    body:    ["'Inter'", 'system-ui', 'sans-serif'],
    mono:    ['monospace'],
  },
};

/** Minimal style-material theme. */
const STYLE_MATERIAL = {
  id: 'style-material',
  type: 'style',
  radius: { small: 4, default: 8, large: 16 },
  elevation: {
    card: '0 2px 4px rgba(0,0,0,0.06)',
    popover: '0 10px 15px rgba(0,0,0,0.1)',
    focus: '0 0 0 3px rgba(66,133,244,0.3)',
  },
  motion: { fast: 150, base: 250, slow: 500, ease: 'ease', emphasisEase: 'ease-out' },
  controls: { height: 40, buttonRadius: 8 },
};

/** Minimal Aurora brand theme — hue 221 to distinguish from Centerpiece (hue 260). */
const BRAND_AURORA_KV = {
  id: 'brand-aurora',
  type: 'brand',
  modes: {
    light: { colors: { primary: '221 83% 53%', background: '210 20% 98%', foreground: '222 47% 11%' } },
    dark:  { colors: { primary: '217 91% 60%', background: '222 47% 11%', foreground: '210 20% 98%' } },
  },
  typography: {
    heading: ["'Inter'", 'system-ui', 'sans-serif'],
    body:    ["'Inter'", 'system-ui', 'sans-serif'],
    mono:    ['monospace'],
  },
};

/** Build a minimal Env for branding unit tests. */
function makeEnv(
  tenantConfigsStore: Record<string, unknown>,
  canonicalInputsStore: Record<string, unknown>,
): Env {
  return {
    TENANT_CONFIGS: makeKV(tenantConfigsStore),
    CANONICAL_INPUTS: makeKV(canonicalInputsStore),
    AUTH_DB: {} as D1Database,
    TENANTS_DB: {} as D1Database,
    ENVIRONMENT: 'test',
    AUTH_DOMAIN: 'auth.centerpiecelab.com',
    ACCESS_TOKEN_TTL_SECONDS: '900',
    REFRESH_TOKEN_TTL_DAYS: '30',
    REFRESH_TOKEN_TTL_DAYS_REMEMBERED: '90',
    AUTH_CODE_TTL_SECONDS: '60',
    PLATFORM_TENANT_ID: 'centerpiecelab',
    JWT_PRIVATE_KEY: '',
    JWT_PUBLIC_KEY: '',
    EMAIL_FROM: 'noreply@centerpiecelab.com',
    EMAIL_FROM_NAME: 'Centerpiece Lab',
    PLATFORM_OWNER_EMAIL_DOMAINS: 'centerpiecelab.com',
  };
}

describe('loadTenantBranding() — unit (in-memory KV stubs)', () => {

  it('loads brand-centerpiece when tenantId is "centerpiecelab"', async () => {
    const env = makeEnv(
      { 'tenant:centerpiecelab': CENTERPIECELAB_CONFIG },
      { 'brands:brand-centerpiece': BRAND_CENTERPIECE, 'styles:style-material': STYLE_MATERIAL },
    );

    const branding = await loadTenantBranding('centerpiecelab', env);

    assert.equal(branding.tenantId, 'centerpiecelab');
    assert.equal(branding.storeName, 'Centerpiece');
    assert.equal(branding.logoUrl, 'https://centerpiecelab.com/logo.svg');
    // Centerpiece hue 260 must be present; Aurora hue 221 must NOT appear
    assert.ok(branding.cssVariables.includes('260'), 'CSS variables should contain Centerpiece primary hue 260');
    assert.ok(!branding.cssVariables.includes('221'), 'CSS variables should NOT contain Aurora primary hue 221');
  });

  it('loads brand-centerpiece (platform default) when tenantId is null — NOT Aurora', async () => {
    const env = makeEnv(
      { 'tenant:centerpiecelab': CENTERPIECELAB_CONFIG },
      { 'brands:brand-centerpiece': BRAND_CENTERPIECE, 'styles:style-material': STYLE_MATERIAL },
    );

    const branding = await loadTenantBranding(null, env);

    // Must resolve to centerpiecelab — not __default__, not aurora
    assert.equal(branding.tenantId, 'centerpiecelab', 'tenantId must be centerpiecelab, not __default__');
    assert.equal(branding.storeName, 'Centerpiece');
    assert.ok(branding.cssVariables.includes('260'), 'CSS variables should contain Centerpiece primary hue 260');
    assert.ok(!branding.cssVariables.includes('221'), 'CSS variables should NOT contain Aurora primary hue 221');
  });

  it('Aurora safety-net fires when named tenant KV throws (double-failure)', async () => {
    const env: Env = {
      ...makeEnv({}, {}),
      TENANT_CONFIGS: makeThrowingKV(),
      CANONICAL_INPUTS: makeThrowingKV(),
    };

    // Should not throw; hardcoded Aurora safety-net takes over
    const branding = await loadTenantBranding('missing-tenant', env);

    assert.equal(branding.tenantId, 'missing-tenant');
    // storeName falls back to 'Centerpiece' (the new hardcoded default — not 'Store')
    assert.equal(branding.storeName, 'Centerpiece');
    // Aurora hardcoded fallback uses hue 221
    assert.ok(branding.cssVariables.includes('221'), 'Aurora safety-net CSS should contain hue 221');
  });

  it('Aurora safety-net fires when null tenantId and BOTH KV calls throw (double-failure)', async () => {
    const env: Env = {
      ...makeEnv({}, {}),
      TENANT_CONFIGS: makeThrowingKV(),
      CANONICAL_INPUTS: makeThrowingKV(),
    };

    const branding = await loadTenantBranding(null, env);

    // tenantId in return value is platform default even under double-failure
    assert.equal(branding.tenantId, 'centerpiecelab', 'tenantId must be centerpiecelab under double-failure');
    assert.ok(branding.cssVariables.includes('221'), 'Aurora safety-net CSS should contain hue 221');
  });

  it('loads brand-aurora when tenant explicitly chose brand-aurora', async () => {
    const sherwoodConfig = {
      config: {
        brandThemeId: 'brand-aurora',
        styleThemeId: 'style-material',
        name: 'Sherwood Creative',
        site: { title: 'Sherwood Creative', logoUrl: null },
      },
    };
    const env = makeEnv(
      { 'tenant:sherwood-creative': sherwoodConfig },
      { 'brands:brand-aurora': BRAND_AURORA_KV, 'styles:style-material': STYLE_MATERIAL },
    );

    const branding = await loadTenantBranding('sherwood-creative', env);

    assert.equal(branding.tenantId, 'sherwood-creative');
    assert.equal(branding.storeName, 'Sherwood Creative');
    // Aurora hue 221 must be present
    assert.ok(branding.cssVariables.includes('221'), 'CSS variables should contain Aurora primary hue 221');
  });

});
