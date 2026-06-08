/**
 * Unit tests for handleLogoutRedirect (GET /api/logout?redirect_uri=…).
 *
 * Tests that:
 * - A valid redirect_uri (controlled platform domain) → 302 to that URI
 * - The refresh cookie is cleared on every path (Set-Cookie present)
 * - An unknown/off-platform redirect_uri → 302 to the auth login page (no open redirect)
 * - A missing redirect_uri → 302 to the auth login page
 *
 * Uses D1/KV mocks — does NOT hit staging endpoints.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleLogoutRedirect } from '../../src/handlers/logout.js';
import type { Env } from '../../src/types.js';

// ─── Mock Builders ───────────────────────────────────────────

function mockEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    AUTH_DB: buildMockD1(),
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
  } as unknown as Env;
}

function buildMockD1(): D1Database {
  const mockStmt = (result: unknown) => ({
    bind: (..._args: unknown[]) => mockStmt(result),
    first: async <T>() => result as T | null,
    run: async () => ({ meta: { changes: 0 } }),
    all: async <T>() => ({ results: [] as T[] }),
  });
  return {
    exec: async () => ({ count: 0, duration: 0, results: [] }),
    prepare: (_sql: string) => mockStmt(null),
    dump: async () => new ArrayBuffer(0),
    batch: async () => [],
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

function makeRequest(url: string, cookieHeader?: string): Request {
  const headers: Record<string, string> = {};
  if (cookieHeader) headers['Cookie'] = cookieHeader;
  return new Request(url, { method: 'GET', headers });
}

// hub.centerpiecelab.dev is a controlled platform domain → passes validation.
const ADMIN_ORIGIN = 'https://hub.centerpiecelab.dev';

// ─── Tests ───────────────────────────────────────────────────

describe('handleLogoutRedirect — valid redirect_uri', () => {
  it('302s to the validated redirect_uri', async () => {
    const url = `https://auth.centerpiecelab.dev/api/logout?redirect_uri=${encodeURIComponent(ADMIN_ORIGIN)}`;
    const res = await handleLogoutRedirect(makeRequest(url, 'cp_rt=sometoken'), mockEnv());

    assert.equal(res.status, 302);
    assert.equal(res.headers.get('Location'), ADMIN_ORIGIN);
  });

  it('clears the refresh cookie', async () => {
    const url = `https://auth.centerpiecelab.dev/api/logout?redirect_uri=${encodeURIComponent(ADMIN_ORIGIN)}`;
    const res = await handleLogoutRedirect(makeRequest(url, 'cp_rt=sometoken'), mockEnv());

    const setCookie = res.headers.get('Set-Cookie') || '';
    assert.ok(setCookie.length > 0, 'expected a Set-Cookie header clearing the refresh cookie');
  });
});

describe('handleLogoutRedirect — unknown redirect_uri (open-redirect guard)', () => {
  it('falls back to the auth login page for an off-platform domain', async () => {
    const evil = encodeURIComponent('https://evil.example.com/phish');
    const url = `https://auth.centerpiecelab.dev/api/logout?redirect_uri=${evil}`;
    const res = await handleLogoutRedirect(makeRequest(url, 'cp_rt=sometoken'), mockEnv());

    assert.equal(res.status, 302);
    const location = res.headers.get('Location') || '';
    assert.ok(location.includes('/login'), `expected login fallback, got: ${location}`);
    assert.ok(!location.includes('evil.example.com'), 'must not redirect to an unvalidated domain');
  });
});

describe('handleLogoutRedirect — missing redirect_uri', () => {
  it('302s to the auth login page and still clears the cookie', async () => {
    const url = 'https://auth.centerpiecelab.dev/api/logout';
    const res = await handleLogoutRedirect(makeRequest(url, 'cp_rt=sometoken'), mockEnv());

    assert.equal(res.status, 302);
    assert.ok((res.headers.get('Location') || '').includes('/login'));
    assert.ok((res.headers.get('Set-Cookie') || '').length > 0);
  });
});
