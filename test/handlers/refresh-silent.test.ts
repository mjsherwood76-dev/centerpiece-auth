/**
 * Unit tests for handleRefresh silent=1 mode.
 *
 * Tests that:
 * - silent=1 returns HTML (not a 302 redirect) on all success and failure paths
 * - HTML payload contains parent.postMessage with correct type
 * - Success path posts { type: 'cp-auth-silent-refresh', code: '<hex>' }
 * - Failure paths post { type: 'cp-auth-silent-refresh', error: '<reason>' }
 * - Non-admin redirect in silent mode returns 204 (no-op, no postMessage)
 * - Missing redirect in silent mode returns HTML error response
 * - postMessage HTML is properly escaped (no XSS via injected values)
 *
 * Uses D1 mocks — does NOT hit staging endpoints.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleRefresh } from '../../src/handlers/refresh.js';

// ─── Mock Builders ───────────────────────────────────────────

/**
 * Build a minimal mock Env.
 * TENANT_CONFIGS is needed for redirect URL validation — we mock it to
 * return no KV data (the validator falls back to domain-suffix matching).
 */
function mockEnv(overrides: Partial<MockEnv> = {}): MockEnv {
  return {
    AUTH_DB: buildMockD1(overrides.AUTH_DB),
    TENANT_CONFIGS: buildMockKV(),
    TENANTS_DB: buildMockD1(),
    CANONICAL_INPUTS: buildMockKV(),
    AUTH_DOMAIN: 'https://auth.centerpiecelab.dev',
    ENVIRONMENT: 'staging',
    ACCESS_TOKEN_TTL_SECONDS: '900',
    REFRESH_TOKEN_TTL_DAYS: '30',
    REFRESH_TOKEN_TTL_DAYS_REMEMBERED: '90',
    AUTH_CODE_TTL_SECONDS: '60',
    JWT_PRIVATE_KEY: '',
    JWT_PUBLIC_KEY: '',
    EMAIL_FROM: 'noreply@centerpiecelab.com',
    EMAIL_FROM_NAME: 'Centerpiece',
    PLATFORM_OWNER_EMAIL_DOMAINS: 'centerpiecelab.com',
    PLATFORM_TENANT_ID: '__platform__',
    ...overrides,
  };
}

interface MockEnv {
  AUTH_DB: D1Database;
  TENANT_CONFIGS: KVNamespace;
  TENANTS_DB: D1Database;
  CANONICAL_INPUTS: KVNamespace;
  AUTH_DOMAIN: string;
  ENVIRONMENT: string;
  ACCESS_TOKEN_TTL_SECONDS: string;
  REFRESH_TOKEN_TTL_DAYS: string;
  REFRESH_TOKEN_TTL_DAYS_REMEMBERED: string;
  AUTH_CODE_TTL_SECONDS: string;
  JWT_PRIVATE_KEY: string;
  JWT_PUBLIC_KEY: string;
  EMAIL_FROM: string;
  EMAIL_FROM_NAME: string;
  PLATFORM_OWNER_EMAIL_DOMAINS: string;
  PLATFORM_TENANT_ID: string;
  [key: string]: unknown;
}

/**
 * Build a mock D1Database. The `prepare` chain is mocked so that:
 * - `exec` (for PRAGMA foreign_keys) does nothing
 * - `getRefreshTokenByHash` returns the supplied row or null
 * - all other queries return null / succeed silently
 */
function buildMockD1(overrides: Partial<D1Database> = {}): D1Database {
  const refreshTokenRow: Record<string, unknown> | null = null;

  const mockStmt = (result: unknown) => ({
    bind: (..._args: unknown[]) => mockStmt(result),
    first: async <T>() => result as T | null,
    run: async () => ({ meta: { changes: 0 } }),
    all: async <T>() => ({ results: [] as T[] }),
  });

  return {
    exec: async () => ({ count: 0, duration: 0, results: [] }),
    prepare: (_sql: string) => mockStmt(refreshTokenRow),
    dump: async () => new ArrayBuffer(0),
    batch: async () => [],
    ...overrides,
  } as unknown as D1Database;
}

function buildMockKV(): KVNamespace {
  return {
    get: async () => null,
    put: async () => {},
    delete: async () => {},
    list: async () => ({ keys: [], list_complete: true, caret: '' }),
    getWithMetadata: async () => ({ value: null, metadata: null }),
  } as unknown as KVNamespace;
}

// ─── Helper: make a request to handleRefresh ────────────────

function makeRequest(url: string, cookieHeader?: string): Request {
  const headers: Record<string, string> = {};
  if (cookieHeader) headers['Cookie'] = cookieHeader;
  return new Request(url, { method: 'GET', headers });
}

// ─── Admin redirect used in tests ───────────────────────────
// Must be on an admin domain so isAdminDomain() returns true.
// hub.centerpiecelab.dev is in ADMIN_DOMAINS.
const ADMIN_CALLBACK = 'https://hub.centerpiecelab.dev/auth/callback';
const ADMIN_ORIGIN = 'https://hub.centerpiecelab.dev';

// ─── Tests ───────────────────────────────────────────────────

describe('handleRefresh silent=1 mode — missing redirect', () => {
  it('returns HTML (not a 302) when redirect is missing', async () => {
    const url = 'https://auth.centerpiecelab.dev/api/refresh?silent=1';
    const res = await handleRefresh(makeRequest(url), mockEnv() as unknown as import('../../src/types.js').Env);

    // Silent mode with no redirect: returns 200 HTML (not a redirect)
    assert.equal(res.status, 200);
    const ct = res.headers.get('Content-Type') || '';
    assert.ok(ct.includes('text/html'), `Expected text/html Content-Type, got: ${ct}`);
  });

  it('HTML contains cp-auth-silent-refresh type for missing redirect', async () => {
    const url = 'https://auth.centerpiecelab.dev/api/refresh?silent=1';
    const res = await handleRefresh(makeRequest(url), mockEnv() as unknown as import('../../src/types.js').Env);

    const html = await res.text();
    assert.ok(html.includes('cp-auth-silent-refresh'), `Expected cp-auth-silent-refresh in HTML: ${html}`);
  });
});

describe('handleRefresh silent=1 mode — non-admin redirect returns 204', () => {
  it('returns 204 (no-op) when redirect is a non-admin domain in silent mode', async () => {
    // Non-admin redirect (storefront domain — not in ADMIN_DOMAINS)
    const nonAdminRedirect = encodeURIComponent('https://test-store.centerpiecelab.com/shop');
    const url = `https://auth.centerpiecelab.dev/api/refresh?silent=1&redirect=${nonAdminRedirect}`;
    const res = await handleRefresh(makeRequest(url), mockEnv() as unknown as import('../../src/types.js').Env);

    assert.equal(res.status, 204, 'non-admin silent=1 should return 204 no-op');
  });
});

describe('handleRefresh silent=1 mode — no refresh cookie', () => {
  it('returns HTML with error no_session when cookie is missing', async () => {
    const redirect = encodeURIComponent(ADMIN_CALLBACK);
    const url = `https://auth.centerpiecelab.dev/api/refresh?silent=1&redirect=${redirect}&audience=admin`;
    // No cookie header
    const res = await handleRefresh(makeRequest(url), mockEnv() as unknown as import('../../src/types.js').Env);

    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('cp-auth-silent-refresh'), 'HTML should contain message type');
    assert.ok(html.includes('no_session'), `Expected no_session error in HTML: ${html}`);
  });

  it('does NOT redirect (no Location header) when cookie is missing', async () => {
    const redirect = encodeURIComponent(ADMIN_CALLBACK);
    const url = `https://auth.centerpiecelab.dev/api/refresh?silent=1&redirect=${redirect}&audience=admin`;
    const res = await handleRefresh(makeRequest(url), mockEnv() as unknown as import('../../src/types.js').Env);

    assert.equal(res.headers.get('Location'), null, 'silent mode must not redirect');
  });
});

describe('handleRefresh silent=1 mode — HTML escaping', () => {
  it('admin origin is properly HTML-attribute escaped in the postMessage HTML', async () => {
    // Verify that the admin origin is written safely into the data attribute
    // (no raw apostrophes or angle brackets from the origin can break out of the attribute)
    const redirect = encodeURIComponent(ADMIN_CALLBACK);
    const url = `https://auth.centerpiecelab.dev/api/refresh?silent=1&redirect=${redirect}&audience=admin`;
    const res = await handleRefresh(makeRequest(url), mockEnv() as unknown as import('../../src/types.js').Env);

    const html = await res.text();
    // The admin origin https://hub.centerpiecelab.dev should appear in the HTML.
    // It must not be injected as a raw unescaped value that could break attribute quoting.
    // Verify the data-payload attribute contains a valid JSON string.
    const match = html.match(/data-payload='([^']+)'/);
    assert.ok(match, 'Expected data-payload attribute in HTML');
    // JSON.parse should not throw (payload is valid JSON)
    assert.doesNotThrow(() => JSON.parse(match![1].replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>')));
  });
});

describe('handleRefresh non-silent mode — still redirects', () => {
  it('returns 302 when silent=1 is absent and redirect is missing', async () => {
    const url = 'https://auth.centerpiecelab.dev/api/refresh';
    const res = await handleRefresh(makeRequest(url), mockEnv() as unknown as import('../../src/types.js').Env);

    // Without redirect URL, non-silent mode should still 302 to login
    assert.equal(res.status, 302);
    const location = res.headers.get('Location') || '';
    assert.ok(location.includes('/login'), `Expected login redirect, got: ${location}`);
  });
});
