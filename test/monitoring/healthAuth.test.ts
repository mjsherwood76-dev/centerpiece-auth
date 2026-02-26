/**
 * Unit tests for Auth Health Endpoint.
 *
 * Tests handleHealth() with mocked D1 bindings.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleHealth } from '../../src/handlers/health.js';

// ── Mock D1 ────────────────────────────────────────────

function createMockEnv(d1Override?: Partial<D1Database>) {
  const healthyD1 = {
    prepare: () => ({
      first: async () => ({ '1': 1 }),
      run: async () => ({ success: true }),
      all: async () => ({ results: [] }),
      raw: async () => [],
      bind: function() { return this; },
    }),
    exec: async () => ({ count: 0, duration: 0 }),
    batch: async () => [],
    dump: async () => new ArrayBuffer(0),
  } as unknown as D1Database;

  return {
    AUTH_DB: d1Override ? { ...healthyD1, ...d1Override } : healthyD1,
    ENVIRONMENT: 'test',
    AUTH_DOMAIN: 'https://auth.test.com',
    ACCESS_TOKEN_TTL_SECONDS: '900',
    REFRESH_TOKEN_TTL_DAYS: '30',
    AUTH_CODE_TTL_SECONDS: '60',
    JWT_PRIVATE_KEY: 'test-key',
    JWT_PUBLIC_KEY: 'test-pub-key',
    EMAIL_FROM: 'test@test.com',
    EMAIL_FROM_NAME: 'Test',
    CANONICAL_INPUTS: {} as KVNamespace,
    TENANT_CONFIGS: {} as KVNamespace,
  };
}

describe('handleHealth', () => {
  it('returns 200 with status: "ok" when D1 is healthy', async () => {
    const env = createMockEnv();
    const response = await handleHealth(env, 'test-corr-id');

    assert.equal(response.status, 200);
    const body = await response.json() as Record<string, unknown>;
    assert.equal(body.status, 'ok');
    assert.equal(body.service, 'centerpiece-auth');
  });

  it('returns version, env, deployedAt, correlationId, and durationMs fields', async () => {
    const env = createMockEnv();
    const response = await handleHealth(env, 'fields-test');
    const body = await response.json() as Record<string, unknown>;

    assert.ok('version' in body, 'should have version');
    assert.ok('env' in body, 'should have env');
    assert.ok('deployedAt' in body, 'should have deployedAt');
    assert.equal(body.correlationId, 'fields-test');
    assert.ok(typeof body.durationMs === 'number', 'durationMs should be a number');
    assert.ok((body.durationMs as number) >= 0, 'durationMs should be non-negative');
  });

  it('D1 probe failure returns status: "degraded" with error info', async () => {
    const failingD1 = {
      prepare: () => ({
        first: async () => { throw new Error('D1 binding unreachable'); },
        bind: function() { return this; },
      }),
    } as unknown as D1Database;

    const env = createMockEnv(failingD1);
    const response = await handleHealth(env, 'degraded-test');

    assert.equal(response.status, 200); // degraded still returns 200
    const body = await response.json() as Record<string, unknown>;
    assert.equal(body.status, 'degraded');

    const subsystems = body.subsystems as Record<string, { status: string; error?: string }>;
    assert.equal(subsystems.d1.status, 'error');
    assert.ok(subsystems.d1.error, 'should have error message');
  });

  it('response has Cache-Control: no-store', async () => {
    const env = createMockEnv();
    const response = await handleHealth(env);

    assert.equal(response.headers.get('Cache-Control'), 'no-store');
  });
});
