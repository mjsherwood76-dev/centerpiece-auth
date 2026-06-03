/**
 * Unit tests for the Phase 3.20 internal customer-auth endpoints.
 *
 *   POST /api/internal/customer-login
 *   POST /api/internal/customer-register
 *   POST /api/internal/customer-forgot-password
 *
 * Uses in-process mocks (mock D1 for AUTH_DB + TENANTS_DB, mock KV) — does NOT
 * hit staging. A real ES256 keypair is generated at setup so the success paths
 * can actually sign + return a JWT.
 *
 * Covers the cross-Worker contract S2/S3 depend on:
 * - internal-secret gate (403 without / with wrong secret)
 * - tenantOrigin validation against TENANTS_DB
 * - constant invalid_credentials failure
 * - customer membership auto-create on success (context 'customer' only)
 * - success body shape { accessToken, refreshToken, expiresIn, user }
 * - register email_exists conflict
 * - forgot-password constant { ok: true }
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { handleInternalCustomerAuth } from '../../src/handlers/internalCustomerAuth.js';
import type { Env } from '../../src/types.js';

const INTERNAL_SECRET = 'test-internal-secret';

// ─── ES256 key generation (real, so signJwt works) ──────────

let jwtPrivateKeyB64 = '';

before(async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const b64 = Buffer.from(pkcs8).toString('base64');
  const pem =
    `-----BEGIN PRIVATE KEY-----\n${(b64.match(/.{1,64}/g) || []).join('\n')}\n-----END PRIVATE KEY-----`;
  // signJwt expects the PEM itself to be base64-encoded (atob in importPrivateKey).
  jwtPrivateKeyB64 = Buffer.from(pem).toString('base64');
});

// ─── In-memory store + mock D1 ──────────────────────────────

interface UserRecord {
  id: string;
  email: string;
  password_hash: string | null;
  name: string;
  email_verified: number;
  avatar_url: string | null;
  created_at: string;
  updated_at: string;
}

interface Store {
  users: UserRecord[];
  memberships: Array<{ id: string; user_id: string; tenant_id: string; context: string; sub_role: string | null }>;
  refreshTokens: Array<Record<string, unknown>>;
  resetTokens: Array<Record<string, unknown>>;
  tenants: Array<{ id: string; name: string; domain: string; status: string }>;
}

function newStore(): Store {
  return { users: [], memberships: [], refreshTokens: [], resetTokens: [], tenants: [] };
}

/**
 * Mock D1 backed by `store`. Recognizes the specific SQL the handler issues via
 * AuthDB: user lookup/insert, membership ensure, refresh-token insert,
 * password-reset insert. TENANTS_DB tenant lookup is handled by `tenantsDb`.
 */
function buildAuthDb(store: Store): D1Database {
  function stmt(sql: string, args: unknown[] = []): D1PreparedStatement {
    const lower = sql.toLowerCase();
    return {
      bind: (...a: unknown[]) => stmt(sql, a),
      first: async <T>() => {
        if (lower.startsWith('select * from users where email')) {
          const email = String(args[0]).toLowerCase();
          return (store.users.find(u => u.email === email) ?? null) as T | null;
        }
        if (lower.startsWith('select * from users where id')) {
          return (store.users.find(u => u.id === args[0]) ?? null) as T | null;
        }
        return null as T | null;
      },
      run: async () => {
        if (lower.startsWith('insert into users')) {
          store.users.push({
            id: String(args[0]),
            email: String(args[1]).toLowerCase(),
            email_verified: Number(args[2]),
            password_hash: (args[3] ?? null) as string | null,
            name: String(args[4] ?? ''),
            avatar_url: (args[5] ?? null) as string | null,
            created_at: '', updated_at: '',
          });
        } else if (lower.startsWith('insert into tenant_memberships')) {
          // ensureMembership: INSERT ... SELECT 'customer', NULL ... WHERE NOT EXISTS(customer row)
          const userId = String(args[1]);
          const tenantId = String(args[2]);
          const exists = store.memberships.some(
            m => m.user_id === userId && m.tenant_id === tenantId && m.context === 'customer',
          );
          if (!exists) {
            store.memberships.push({
              id: String(args[0]), user_id: userId, tenant_id: tenantId,
              context: 'customer', sub_role: null,
            });
          }
        } else if (lower.startsWith('insert into refresh_tokens')) {
          store.refreshTokens.push({ args });
        } else if (lower.startsWith('insert into password_reset_tokens')) {
          store.resetTokens.push({ token_hash: args[0], user_id: args[1], expires_at: args[2] });
        }
        return { meta: { changes: 1 } } as unknown as D1Result;
      },
      all: async <T>() => ({ results: [] as T[] } as unknown as D1Result<T>),
      raw: async () => [],
    } as unknown as D1PreparedStatement;
  }

  return {
    prepare: (sql: string) => stmt(sql),
    exec: async () => ({ count: 0, duration: 0 }),
    dump: async () => new ArrayBuffer(0),
    batch: async () => [],
  } as unknown as D1Database;
}

/** Mock TENANTS_DB: getTenantNames issues `SELECT id, name, domain FROM tenants WHERE id IN (...) AND status = 'active'`. */
function buildTenantsDb(store: Store): D1Database {
  function stmt(args: unknown[] = []): D1PreparedStatement {
    return {
      bind: (...a: unknown[]) => stmt(a),
      first: async () => null,
      run: async () => ({ meta: { changes: 0 } } as unknown as D1Result),
      all: async <T>() => {
        const ids = args.map(String);
        const rows = store.tenants
          .filter(t => ids.includes(t.id) && t.status === 'active')
          .map(t => ({ id: t.id, name: t.name, domain: t.domain }));
        return { results: rows as unknown as T[] } as unknown as D1Result<T>;
      },
    } as unknown as D1PreparedStatement;
  }
  return {
    prepare: () => stmt(),
    exec: async () => ({ count: 0, duration: 0 }),
    dump: async () => new ArrayBuffer(0),
    batch: async () => [],
  } as unknown as D1Database;
}

function buildKv(): KVNamespace {
  return {
    get: async () => null,
    put: async () => {},
    delete: async () => {},
    list: async () => ({ keys: [], list_complete: true, cacheStatus: null }),
    getWithMetadata: async () => ({ value: null, metadata: null }),
  } as unknown as KVNamespace;
}

function mockEnv(store: Store): Env {
  return {
    AUTH_DB: buildAuthDb(store),
    TENANTS_DB: buildTenantsDb(store),
    CANONICAL_INPUTS: buildKv(),
    TENANT_CONFIGS: buildKv(),
    ENVIRONMENT: 'staging',
    AUTH_DOMAIN: 'https://auth.centerpiecelab.dev',
    ACCESS_TOKEN_TTL_SECONDS: '900',
    REFRESH_TOKEN_TTL_DAYS: '30',
    REFRESH_TOKEN_TTL_DAYS_REMEMBERED: '90',
    AUTH_CODE_TTL_SECONDS: '60',
    PLATFORM_TENANT_ID: '__platform__',
    JWT_PRIVATE_KEY: jwtPrivateKeyB64,
    JWT_PUBLIC_KEY: '',
    EMAIL_FROM: 'noreply@centerpiecelab.com',
    EMAIL_FROM_NAME: 'Centerpiece',
    PLATFORM_OWNER_EMAIL_DOMAINS: 'centerpiecelab.com',
    PLATFORM_DOMAIN: 'centerpiecelab.dev',
    AUTH_ISSUER_URL: 'https://auth.centerpiecelab.dev',
    INTERNAL_SECRET: INTERNAL_SECRET,
  } as unknown as Env;
}

// PBKDF2 hash (matches src/crypto/passwords.ts) — used to seed a known user.
import { hashPassword } from '../../src/crypto/passwords.js';

function makeRequest(path: string, body: unknown, secret?: string): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (secret !== undefined) headers['X-CP-Internal-Secret'] = secret;
  return new Request(`https://auth.centerpiecelab.dev${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

const TENANT = { id: 'sherwood-creative', name: 'Sherwood Creative', domain: 'www.sherwood-creative.com', status: 'active' };
const ORIGIN = 'https://www.sherwood-creative.com';

// ─── Internal-secret gate ───────────────────────────────────

describe('internal-secret gate', () => {
  it('returns 403 when secret header is missing', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login', { email: 'a@b.com', password: 'x', tenantId: TENANT.id, tenantOrigin: ORIGIN }),
      mockEnv(store),
    );
    assert.equal(res.status, 403);
  });

  it('returns 403 when secret is wrong', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login', {}, 'wrong'),
      mockEnv(store),
    );
    assert.equal(res.status, 403);
  });
});

// ─── tenantOrigin validation ────────────────────────────────

describe('tenantOrigin validation', () => {
  it('rejects an origin that does not match the tenant domain', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'a@b.com', password: 'x', tenantId: TENANT.id, tenantOrigin: 'https://attacker.example' },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_tenant_origin');
  });

  it('rejects when the tenant is unknown / inactive', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'a@b.com', password: 'x', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
  });
});

// ─── Login ──────────────────────────────────────────────────

describe('POST /api/internal/customer-login', () => {
  it('returns constant invalid_credentials for unknown user', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'nobody@b.com', password: 'whatever', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 401);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_credentials');
  });

  it('returns invalid_credentials for wrong password', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    store.users.push({
      id: 'u1', email: 'jane@b.com', password_hash: await hashPassword('correct-horse'),
      name: 'Jane', email_verified: 1, avatar_url: null, created_at: '', updated_at: '',
    });
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'jane@b.com', password: 'wrong', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 401);
  });

  it('issues tokens + auto-creates a customer membership on success', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    store.users.push({
      id: 'u1', email: 'jane@b.com', password_hash: await hashPassword('correct-horse'),
      name: 'Jane', email_verified: 1, avatar_url: null, created_at: '', updated_at: '',
    });
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'jane@b.com', password: 'correct-horse', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as {
      accessToken: string; refreshToken: string; expiresIn: number;
      user: { id: string; email: string; displayName: string };
    };
    assert.ok(body.accessToken && body.accessToken.split('.').length === 3, 'accessToken is a JWT');
    assert.ok(body.refreshToken && body.refreshToken.length >= 32, 'refreshToken present');
    assert.equal(body.expiresIn, 900);
    assert.deepEqual(body.user, { id: 'u1', email: 'jane@b.com', displayName: 'Jane' });

    // Membership auto-created with context 'customer' only.
    assert.equal(store.memberships.length, 1);
    assert.equal(store.memberships[0].context, 'customer');
    assert.equal(store.memberships[0].sub_role, null);
    assert.equal(store.refreshTokens.length, 1, 'refresh token persisted');
  });
});

// ─── Register ───────────────────────────────────────────────

describe('POST /api/internal/customer-register', () => {
  it('creates a user + customer membership and returns tokens', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-register',
        { email: 'new@b.com', password: 'longenough1', tenantId: TENANT.id, tenantOrigin: ORIGIN, displayName: 'New User' },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as { user: { email: string; displayName: string } };
    assert.equal(body.user.email, 'new@b.com');
    assert.equal(body.user.displayName, 'New User');
    assert.equal(store.users.length, 1);
    assert.equal(store.memberships.length, 1);
    assert.equal(store.memberships[0].context, 'customer');
  });

  it('returns email_exists (409) when the email is taken', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    store.users.push({
      id: 'u1', email: 'dupe@b.com', password_hash: await hashPassword('x'),
      name: 'Dupe', email_verified: 1, avatar_url: null, created_at: '', updated_at: '',
    });
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-register',
        { email: 'dupe@b.com', password: 'longenough1', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 409);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'email_exists');
  });

  it('rejects a weak password (400)', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-register',
        { email: 'new@b.com', password: 'short', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
  });
});

// ─── Forgot password ────────────────────────────────────────

describe('POST /api/internal/customer-forgot-password', () => {
  it('returns constant { ok: true } for unknown email', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-forgot-password',
        { email: 'ghost@b.com', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, boolean>;
    assert.equal(body.ok, true);
    assert.equal(store.resetTokens.length, 0, 'no reset token for unknown email');
  });

  it('returns { ok: true } even when tenantOrigin is invalid (no leak)', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-forgot-password',
        { email: 'ghost@b.com', tenantId: TENANT.id, tenantOrigin: 'https://attacker.example' },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, boolean>;
    assert.equal(body.ok, true);
  });
});
