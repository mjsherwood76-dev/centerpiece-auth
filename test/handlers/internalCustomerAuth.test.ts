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
 * - tenant-scope + privileged-exclusion (Fix — Customer Storefront Auth S1):
 *   forgot only emails a genuine customer of THIS tenant with no privileged
 *   context; login + register refuse any privileged account (incl. one who is
 *   also a customer of this tenant — block-both) with the same constant shapes
 * - customer-refresh rotation: new tokens on valid refresh, theft detection on
 *   reuse (revoked token → family revoked → 401), expiry → 401 (Phase 3.20 S3)
 * - customer-logout: revokes the presented refresh token, idempotent ok:true
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

interface RefreshTokenRecord {
  id: string;
  user_id: string;
  token_hash: string;
  family_id: string;
  expires_at: number;
  revoked_at: string | null;
  login_iat: number;
}

interface MembershipRecord {
  id: string;
  user_id: string;
  tenant_id: string;
  context: string;
  sub_role: string | null;
  status: string;
}

interface Store {
  users: UserRecord[];
  memberships: MembershipRecord[];
  refreshTokens: RefreshTokenRecord[];
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
        if (lower.startsWith('select * from refresh_tokens where token_hash')) {
          return (store.refreshTokens.find(t => t.token_hash === args[0]) ?? null) as T | null;
        }
        // hasCustomerMembership: SELECT 1 FROM tenant_memberships
        //   WHERE user_id = ? AND tenant_id = ? AND context = 'customer' AND status = 'active' LIMIT 1
        if (lower.startsWith('select 1 from tenant_memberships')) {
          const userId = String(args[0]);
          const tenantId = String(args[1]);
          const hit = store.memberships.some(
            m => m.user_id === userId && m.tenant_id === tenantId
              && m.context === 'customer' && m.status === 'active',
          );
          return (hit ? ({ 1: 1 } as unknown as T) : null);
        }
        return null as T | null;
      },
      run: async () => {
        if (lower.startsWith('update tenant_memberships set status')) {
          // suspendMemberships: SET status='suspended' WHERE user_id=? AND
          //   tenant_id=? AND context=? AND sub_role != 'owner' AND status='active'
          const userId = String(args[0]);
          const tenantId = String(args[1]);
          const context = String(args[2]);
          let changes = 0;
          for (const m of store.memberships) {
            if (m.user_id === userId && m.tenant_id === tenantId && m.context === context
                && m.sub_role !== 'owner' && m.status === 'active') {
              m.status = 'suspended';
              changes++;
            }
          }
          return { meta: { changes } } as unknown as D1Result;
        }
        if (lower.startsWith('update refresh_tokens set revoked_at')) {
          // Two shapes: WHERE token_hash = ? [AND revoked_at IS NULL]  (single revoke / rotate-revoke)
          //             WHERE family_id = ? AND revoked_at IS NULL      (family revoke)
          if (lower.includes('where family_id')) {
            const familyId = String(args[0]);
            for (const t of store.refreshTokens) {
              if (t.family_id === familyId && t.revoked_at === null) t.revoked_at = 'now';
            }
          } else {
            const hash = String(args[0]);
            for (const t of store.refreshTokens) {
              if (t.token_hash === hash && t.revoked_at === null) t.revoked_at = 'now';
            }
          }
          return { meta: { changes: 1 } } as unknown as D1Result;
        }
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
              context: 'customer', sub_role: null, status: 'active',
            });
          }
        } else if (lower.startsWith('insert into refresh_tokens')) {
          store.refreshTokens.push({
            id: String(args[0]),
            user_id: String(args[1]),
            token_hash: String(args[2]),
            family_id: String(args[3]),
            expires_at: Number(args[4]),
            revoked_at: null,
            login_iat: Number(args[10] ?? 0),
          });
        } else if (lower.startsWith('insert into password_reset_tokens')) {
          store.resetTokens.push({ token_hash: args[0], user_id: args[1], expires_at: args[2] });
        }
        return { meta: { changes: 1 } } as unknown as D1Result;
      },
      all: async <T>() => {
        // getAdminMemberships (privileged check): SELECT tenant_id, context, sub_role
        //   FROM tenant_memberships WHERE user_id = ? AND context != 'customer' AND status = 'active'
        if (lower.startsWith('select tenant_id, context, sub_role from tenant_memberships')) {
          const userId = String(args[0]);
          const rows = store.memberships
            .filter(m => m.user_id === userId && m.context !== 'customer' && m.status === 'active')
            .map(m => ({ tenant_id: m.tenant_id, context: m.context, sub_role: m.sub_role }));
          return { results: rows as unknown as T[] } as unknown as D1Result<T>;
        }
        return { results: [] as T[] } as unknown as D1Result<T>;
      },
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

/**
 * TENANT_CONFIGS KV stub that returns a gating config for `tenant:<id>` lookups.
 * Mirrors the D1→KV wrapper shape (`{ config: { ... } }`) loadTenantGating reads.
 */
function buildGatingKv(configsByTenant: Record<string, unknown>): KVNamespace {
  return {
    get: async (key: string) => {
      const id = key.replace(/^tenant:/, '');
      return (configsByTenant[id] ?? null) as never;
    },
    put: async () => {},
    delete: async () => {},
    list: async () => ({ keys: [], list_complete: true, cacheStatus: null }),
    getWithMetadata: async () => ({ value: null, metadata: null }),
  } as unknown as KVNamespace;
}

function mockEnv(store: Store, tenantConfigs?: KVNamespace): Env {
  return {
    AUTH_DB: buildAuthDb(store),
    TENANTS_DB: buildTenantsDb(store),
    CANONICAL_INPUTS: buildKv(),
    TENANT_CONFIGS: tenantConfigs ?? buildKv(),
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
    // Disable breach check in unit tests — breach-check logic is tested in
    // test/security/breachedPassword.test.ts; here we test handler logic only.
    PASSWORD_BREACH_CHECK_ENABLED: 'false',
  } as unknown as Env;
}

// PBKDF2 hash (matches src/crypto/passwords.ts) — used to seed a known user.
import { hashPassword } from '../../src/crypto/passwords.js';
// SHA-256 refresh-token hashing — used to seed a known refresh token whose
// plaintext we control, so the refresh/logout tests can present it.
import { hashRefreshToken } from '../../src/crypto/refreshTokens.js';

const NOW = () => Math.floor(Date.now() / 1000);

async function seedRefreshToken(
  store: Store,
  opts: { userId: string; plaintext: string; familyId?: string; expiresAt?: number; revoked?: boolean },
): Promise<void> {
  store.refreshTokens.push({
    id: `rt-${store.refreshTokens.length}`,
    user_id: opts.userId,
    token_hash: await hashRefreshToken(opts.plaintext),
    family_id: opts.familyId ?? 'fam-1',
    expires_at: opts.expiresAt ?? NOW() + 86400,
    revoked_at: opts.revoked ? 'now' : null,
    login_iat: NOW(),
  });
}

/** Seed a user with a known password into the store. */
async function seedUserWithPassword(
  store: Store,
  opts: { id: string; email: string; password: string; name?: string },
): Promise<void> {
  store.users.push({
    id: opts.id, email: opts.email.toLowerCase(),
    password_hash: await hashPassword(opts.password),
    name: opts.name ?? 'Test', email_verified: 1, avatar_url: null,
    created_at: '', updated_at: '',
  });
}

/** Seed a membership row into the store. */
function seedMembership(
  store: Store,
  opts: { userId: string; tenantId: string; context: string; subRole?: string | null; status?: string },
): void {
  store.memberships.push({
    id: `m-${store.memberships.length}`,
    user_id: opts.userId,
    tenant_id: opts.tenantId,
    context: opts.context,
    sub_role: opts.subRole ?? null,
    status: opts.status ?? 'active',
  });
}

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

  it('refuses a privileged account with constant invalid_credentials — no token, no membership', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'seller@b.com', password: 'correct-horse', name: 'Seller' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'seller', subRole: 'owner' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'seller@b.com', password: 'correct-horse', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 401);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_credentials');
    // No storefront token issued, no customer membership auto-created.
    assert.equal(store.refreshTokens.length, 0, 'no refresh token for privileged login');
    assert.ok(
      !store.memberships.some(m => m.context === 'customer'),
      'no customer membership auto-created for privileged login',
    );
  });

  it('refuses a privileged user who is ALSO a customer of this tenant (block-both)', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'mike@b.com', password: 'correct-horse', name: 'Mike' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'platform', subRole: 'owner' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'mike@b.com', password: 'correct-horse', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 401);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_credentials');
    assert.equal(store.refreshTokens.length, 0, 'no token issued even though also a customer');
  });

  it('still logs in a customer-only user who has an existing customer membership', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'jane@b.com', password: 'correct-horse', name: 'Jane' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'jane@b.com', password: 'correct-horse', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    assert.equal(store.refreshTokens.length, 1, 'token issued for customer-only user');
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

  it('returns email_exists (409) for a privileged account and attaches no customer membership', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'seller@b.com', password: 'x', name: 'Seller' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'seller', subRole: 'owner' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-register',
        { email: 'seller@b.com', password: 'longenough1', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 409);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'email_exists');
    assert.ok(
      !store.memberships.some(m => m.context === 'customer'),
      'no customer membership attached to a privileged account',
    );
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

  it('sends a reset for a genuine customer OF THIS TENANT', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'cust@b.com', password: 'x' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-forgot-password',
        { email: 'cust@b.com', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, boolean>;
    assert.equal(body.ok, true);
    assert.equal(store.resetTokens.length, 1, 'reset token issued for real customer');
  });

  it('does NOT send a reset for a user who is not a customer of this tenant', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'other@b.com', password: 'x' });
    // Customer of a DIFFERENT tenant only.
    seedMembership(store, { userId: 'u1', tenantId: 'some-other-tenant', context: 'customer' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-forgot-password',
        { email: 'other@b.com', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, boolean>;
    assert.equal(body.ok, true);
    assert.equal(store.resetTokens.length, 0, 'no reset token for non-customer-of-tenant');
  });

  it('does NOT send a reset for a privileged account (even if also a customer of this tenant)', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'mike@b.com', password: 'x' });
    // Holds a customer membership on this tenant AND a platform context.
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'platform', subRole: 'owner' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-forgot-password',
        { email: 'mike@b.com', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, boolean>;
    assert.equal(body.ok, true);
    assert.equal(store.resetTokens.length, 0, 'no reset token for privileged account');
  });
});

// ─── Refresh (rotation + theft detection) ───────────────────

describe('POST /api/internal/customer-refresh', () => {
  function seedUser(store: Store): void {
    store.users.push({
      id: 'u1', email: 'jane@b.com', password_hash: null,
      name: 'Jane', email_verified: 1, avatar_url: null, created_at: '', updated_at: '',
    });
  }

  it('rotates a valid refresh token and issues a new access + refresh', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    seedUser(store);
    await seedRefreshToken(store, { userId: 'u1', plaintext: 'old-refresh-token' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-refresh',
        { refreshToken: 'old-refresh-token', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as {
      accessToken: string; refreshToken: string; expiresIn: number;
      user: { id: string; email: string; displayName: string };
    };
    assert.ok(body.accessToken.split('.').length === 3, 'new access token is a JWT');
    assert.ok(body.refreshToken.length >= 32, 'new refresh token present');
    assert.notEqual(body.refreshToken, 'old-refresh-token', 'refresh token rotated');
    assert.equal(body.expiresIn, 900);
    assert.deepEqual(body.user, { id: 'u1', email: 'jane@b.com', displayName: 'Jane' });

    // Old token revoked; new token persisted in the same family.
    const oldHash = await hashRefreshToken('old-refresh-token');
    const newHash = await hashRefreshToken(body.refreshToken);
    const oldRow = store.refreshTokens.find(t => t.token_hash === oldHash)!;
    const newRow = store.refreshTokens.find(t => t.token_hash === newHash)!;
    assert.notEqual(oldRow.revoked_at, null, 'old refresh token revoked');
    assert.equal(newRow.revoked_at, null, 'new refresh token active');
    assert.equal(newRow.family_id, oldRow.family_id, 'rotation stays in same family');
  });

  it('returns 401 invalid_refresh for an unknown token', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-refresh',
        { refreshToken: 'does-not-exist', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 401);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_refresh');
  });

  it('detects reuse of a revoked token and revokes the whole family', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    seedUser(store);
    // Two tokens in the same family; the presented one is already revoked (reuse).
    await seedRefreshToken(store, { userId: 'u1', plaintext: 'stolen', familyId: 'fam-x', revoked: true });
    await seedRefreshToken(store, { userId: 'u1', plaintext: 'sibling', familyId: 'fam-x' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-refresh',
        { refreshToken: 'stolen', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 401);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_refresh');

    // Theft detection: the still-active sibling in the family is now revoked.
    const siblingHash = await hashRefreshToken('sibling');
    const sibling = store.refreshTokens.find(t => t.token_hash === siblingHash)!;
    assert.notEqual(sibling.revoked_at, null, 'family revoked on reuse');
  });

  it('returns 401 invalid_refresh for an expired token', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    seedUser(store);
    await seedRefreshToken(store, { userId: 'u1', plaintext: 'expired-token', expiresAt: NOW() - 10 });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-refresh',
        { refreshToken: 'expired-token', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 401);
  });

  it('rejects when tenantOrigin does not match the tenant', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    seedUser(store);
    await seedRefreshToken(store, { userId: 'u1', plaintext: 'tok' });
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-refresh',
        { refreshToken: 'tok', tenantId: TENANT.id, tenantOrigin: 'https://attacker.example' },
        INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
  });
});

// ─── Logout (server-side revoke) ────────────────────────────

describe('POST /api/internal/customer-logout', () => {
  it('revokes the presented refresh token and returns ok:true', async () => {
    const store = newStore();
    await seedRefreshToken(store, { userId: 'u1', plaintext: 'live-token' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-logout', { refreshToken: 'live-token' }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, boolean>;
    assert.equal(body.ok, true);

    const liveHash = await hashRefreshToken('live-token');
    const row = store.refreshTokens.find(t => t.token_hash === liveHash)!;
    assert.notEqual(row.revoked_at, null, 'refresh token revoked on logout');
  });

  it('returns ok:true even when no/unknown token is presented (idempotent)', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-logout', {}, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, boolean>;
    assert.equal(body.ok, true);
  });

  it('still requires the internal secret', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-logout', { refreshToken: 'x' }),
      mockEnv(store),
    );
    assert.equal(res.status, 403);
  });
});

// ─── Gated-tenant domain allowlist (Phase 3.25) ─────────────

/** TENANT_CONFIGS stub gating TENANT.id with a domain-allowlist policy. */
function gatedConfigs(domains: string[]): KVNamespace {
  return buildGatingKv({
    [TENANT.id]: {
      config: {
        defaultAccessRequirement: { policy: 'domain-allowlist' },
        allowedEmailDomains: domains,
      },
    },
  });
}

describe('domain-allowlist enforcement — login', () => {
  it('refuses a non-allowed domain with constant invalid_credentials (no token)', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'outsider@gmail.com', password: 'correct-horse' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'outsider@gmail.com', password: 'correct-horse', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store, gatedConfigs(['valhallan.com'])),
    );
    assert.equal(res.status, 401);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_credentials');
    assert.equal(store.refreshTokens.length, 0, 'no token issued for non-allowed domain');
  });

  it('allows an on-allowlist domain to log in', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUserWithPassword(store, { id: 'u1', email: 'member@valhallan.com', password: 'correct-horse' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-login',
        { email: 'member@valhallan.com', password: 'correct-horse', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store, gatedConfigs(['valhallan.com', 'xpleague.com'])),
    );
    assert.equal(res.status, 200);
    assert.equal(store.refreshTokens.length, 1, 'token issued for allowed domain');
  });
});

describe('domain-allowlist enforcement — register', () => {
  it('refuses a non-allowed domain (domain_not_allowed, no user created)', async () => {
    const store = newStore();
    store.tenants.push(TENANT);

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-register',
        { email: 'outsider@gmail.com', password: 'longenough1', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store, gatedConfigs(['valhallan.com'])),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'domain_not_allowed');
    assert.equal(store.users.length, 0, 'no user created for non-allowed domain');
  });

  it('allows an on-allowlist domain to register', async () => {
    const store = newStore();
    store.tenants.push(TENANT);

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-register',
        { email: 'newmember@xpleague.com', password: 'longenough1', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store, gatedConfigs(['valhallan.com', 'xpleague.com'])),
    );
    assert.equal(res.status, 200);
    assert.equal(store.users.length, 1, 'user created for allowed domain');
    assert.equal(store.memberships[0].context, 'customer');
  });

  it('does NOT gate a public (ungated) tenant — any domain registers', async () => {
    const store = newStore();
    store.tenants.push(TENANT);

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/customer-register',
        { email: 'anyone@gmail.com', password: 'longenough1', tenantId: TENANT.id, tenantOrigin: ORIGIN },
        INTERNAL_SECRET),
      mockEnv(store), // default KV → ungated
    );
    assert.equal(res.status, 200);
    assert.equal(store.users.length, 1, 'ungated tenant accepts any domain');
  });
});

// ─── Revoke customer membership (Phase 3.25) ────────────────

describe('POST /api/internal/revoke-customer-membership', () => {
  it('requires the internal secret', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/revoke-customer-membership', { userId: 'u1', tenantId: TENANT.id }),
      mockEnv(store),
    );
    assert.equal(res.status, 403);
  });

  it('rejects a missing userId/tenantId', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/revoke-customer-membership', { userId: 'u1' }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
  });

  it('suspends an active customer membership (constraint-safe status)', async () => {
    const store = newStore();
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/revoke-customer-membership', { userId: 'u1', tenantId: TENANT.id }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as { revoked: boolean; count: number };
    assert.equal(body.revoked, true);
    assert.equal(body.count, 1);
    assert.equal(store.memberships[0].status, 'suspended', 'membership set to suspended, not revoked');
  });

  it('only touches the customer context, leaving privileged memberships alone', async () => {
    const store = newStore();
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'seller', subRole: 'owner' });

    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/revoke-customer-membership', { userId: 'u1', tenantId: TENANT.id }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const customer = store.memberships.find(m => m.context === 'customer')!;
    const seller = store.memberships.find(m => m.context === 'seller')!;
    assert.equal(customer.status, 'suspended');
    assert.equal(seller.status, 'active', 'seller membership untouched');
  });

  it('is idempotent when no active membership exists (count 0, ok:true)', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest('/api/internal/revoke-customer-membership', { userId: 'ghost', tenantId: TENANT.id }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as { revoked: boolean; count: number };
    assert.equal(body.count, 0);
  });
});
