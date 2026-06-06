/**
 * Unit tests for POST /api/internal/customer-reset-password
 * (Fix — Customer Storefront Auth Tenant-Scoping, Session 3).
 *
 * Service-Binding-only endpoint that completes a tenant-scoped customer reset:
 * verify token (hash lookup, not expired, not used) → re-evaluate membership AT
 * COMPLETION (customer of THIS tenant AND not privileged) → set password +
 * one-shot consume + revoke all refresh tokens. Failure shapes are constant
 * (`reset_failed`) so the caller cannot learn WHY.
 *
 * Uses in-process mocks (mock D1 for AUTH_DB + TENANTS_DB, mock KV) — does NOT
 * hit staging. Mirrors test/handlers/internalCustomerAuth.test.ts.
 *
 * Coverage:
 * - valid token + current customer-of-this-tenant → ok, password changed,
 *   token consumed, all refresh tokens revoked
 * - user holds a privileged context at completion → refused (reset_failed),
 *   token still consumed (one-shot), password NOT changed
 * - token whose user is NOT a customer of the completing tenant → refused
 * - wrong / expired / already-used token → refused
 * - internal-secret gate + tenantOrigin validation + input validation
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { handleInternalCustomerAuth } from '../../src/handlers/internalCustomerAuth.js';
import type { Env } from '../../src/types.js';
import { hashPassword, verifyPassword } from '../../src/crypto/passwords.js';
import { sha256Hex } from '../../src/crypto/jwt.js';

const INTERNAL_SECRET = 'test-internal-secret';

// ─── ES256 key generation (real, so any signing path works) ──
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

interface ResetTokenRecord {
  token_hash: string;
  user_id: string;
  expires_at: number;
  used_at: string | null;
}

interface Store {
  users: UserRecord[];
  memberships: MembershipRecord[];
  refreshTokens: RefreshTokenRecord[];
  resetTokens: ResetTokenRecord[];
  tenants: Array<{ id: string; name: string; domain: string; status: string }>;
}

function newStore(): Store {
  return { users: [], memberships: [], refreshTokens: [], resetTokens: [], tenants: [] };
}

/**
 * Mock D1 backed by `store`. Recognizes the SQL the reset handler issues via
 * AuthDB: password-reset-token consume (select + update used_at), user lookup,
 * user password update, all-sessions revoke, and the membership checks.
 */
function buildAuthDb(store: Store): D1Database {
  function stmt(sql: string, args: unknown[] = []): D1PreparedStatement {
    const lower = sql.toLowerCase();
    return {
      bind: (...a: unknown[]) => stmt(sql, a),
      first: async <T>() => {
        if (lower.startsWith('select * from users where id')) {
          return (store.users.find(u => u.id === args[0]) ?? null) as T | null;
        }
        if (lower.startsWith('select user_id, expires_at from password_reset_tokens')) {
          // consumePasswordResetToken: WHERE token_hash = ? AND used_at IS NULL
          const hash = String(args[0]);
          const row = store.resetTokens.find(t => t.token_hash === hash && t.used_at === null);
          return (row ? ({ user_id: row.user_id, expires_at: row.expires_at } as unknown as T) : null);
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
        if (lower.startsWith('update password_reset_tokens set used_at')) {
          const hash = String(args[0]);
          for (const t of store.resetTokens) {
            if (t.token_hash === hash) t.used_at = 'now';
          }
        } else if (lower.startsWith('update users set password_hash')) {
          const userId = String(args[1]);
          const u = store.users.find(x => x.id === userId);
          if (u) u.password_hash = String(args[0]);
        } else if (lower.startsWith('update refresh_tokens set revoked_at')) {
          // revokeAllRefreshTokensForUser: WHERE user_id = ? AND revoked_at IS NULL
          const userId = String(args[0]);
          for (const t of store.refreshTokens) {
            if (t.user_id === userId && t.revoked_at === null) t.revoked_at = 'now';
          }
        }
        return { meta: { changes: 1 } } as unknown as D1Result;
      },
      all: async <T>() => {
        // getAdminMemberships (privileged check)
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
    // Disable breach check in unit tests — breach-check logic is tested in
    // test/security/breachedPassword.test.ts; here we test handler logic only.
    PASSWORD_BREACH_CHECK_ENABLED: 'false',
  } as unknown as Env;
}

const NOW = () => Math.floor(Date.now() / 1000);

async function seedResetToken(
  store: Store,
  opts: { userId: string; plaintext: string; expiresAt?: number; used?: boolean },
): Promise<void> {
  store.resetTokens.push({
    token_hash: await sha256Hex(opts.plaintext),
    user_id: opts.userId,
    expires_at: opts.expiresAt ?? NOW() + 3600,
    used_at: opts.used ? 'now' : null,
  });
}

async function seedUser(
  store: Store,
  opts: { id: string; email: string; password?: string },
): Promise<void> {
  store.users.push({
    id: opts.id, email: opts.email.toLowerCase(),
    password_hash: opts.password ? await hashPassword(opts.password) : null,
    name: 'Test', email_verified: 1, avatar_url: null, created_at: '', updated_at: '',
  });
}

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

function seedRefreshToken(store: Store, opts: { userId: string; id?: string }): void {
  store.refreshTokens.push({
    id: opts.id ?? `rt-${store.refreshTokens.length}`,
    user_id: opts.userId,
    token_hash: `hash-${store.refreshTokens.length}`,
    family_id: 'fam-1',
    expires_at: NOW() + 86400,
    revoked_at: null,
    login_iat: NOW(),
  });
}

function makeRequest(body: unknown, secret?: string): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (secret !== undefined) headers['X-CP-Internal-Secret'] = secret;
  return new Request('https://auth.centerpiecelab.dev/api/internal/customer-reset-password', {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

const TENANT = { id: 'sherwood-creative', name: 'Sherwood Creative', domain: 'www.sherwood-creative.com', status: 'active' };
const ORIGIN = 'https://www.sherwood-creative.com';

describe('POST /api/internal/customer-reset-password', () => {
  // ── gate + origin + input validation ──

  it('returns 403 without the internal secret', async () => {
    const store = newStore();
    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 't', newPassword: 'longenough1', tenantId: TENANT.id, tenantOrigin: ORIGIN }),
      mockEnv(store),
    );
    assert.equal(res.status, 403);
  });

  it('returns invalid_tenant_origin when origin does not match the tenant', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 't', newPassword: 'longenough1', tenantId: TENANT.id, tenantOrigin: 'https://attacker.example' }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_tenant_origin');
  });

  it('returns invalid_request for a missing token', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest({ newPassword: 'longenough1', tenantId: TENANT.id, tenantOrigin: ORIGIN }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_request');
  });

  it('returns invalid_request for a weak new password', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 't', newPassword: 'short', tenantId: TENANT.id, tenantOrigin: ORIGIN }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'invalid_request');
  });

  // ── happy path ──

  it('resets a current customer-of-this-tenant: password changed, token consumed, refresh revoked', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUser(store, { id: 'u1', email: 'cust@b.com', password: 'old-password' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });
    await seedResetToken(store, { userId: 'u1', plaintext: 'reset-tok' });
    seedRefreshToken(store, { userId: 'u1' });
    seedRefreshToken(store, { userId: 'u1' });

    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 'reset-tok', newPassword: 'brand-new-password', tenantId: TENANT.id, tenantOrigin: ORIGIN }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 200);
    const body = await res.json() as Record<string, boolean>;
    assert.equal(body.ok, true);

    // Password actually changed to the new value (PBKDF2).
    const u = store.users.find(x => x.id === 'u1')!;
    assert.ok(await verifyPassword('brand-new-password', u.password_hash!), 'password set to new value');
    assert.equal(await verifyPassword('old-password', u.password_hash!), false, 'old password no longer valid');

    // Token consumed one-shot.
    assert.notEqual(store.resetTokens[0].used_at, null, 'token marked used');

    // All refresh tokens for the user revoked.
    assert.ok(store.refreshTokens.every(t => t.revoked_at !== null), 'all sessions revoked');
  });

  // ── privileged-at-completion refusal ──

  it('refuses (reset_failed) when the user holds a privileged context at completion — token still burned, password unchanged', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUser(store, { id: 'u1', email: 'mike@b.com', password: 'old-password' });
    // Customer of this tenant AND privileged (gained between issue and completion).
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'platform', subRole: 'owner' });
    await seedResetToken(store, { userId: 'u1', plaintext: 'reset-tok' });

    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 'reset-tok', newPassword: 'brand-new-password', tenantId: TENANT.id, tenantOrigin: ORIGIN }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'reset_failed');

    // Password NOT changed.
    const u = store.users.find(x => x.id === 'u1')!;
    assert.ok(await verifyPassword('old-password', u.password_hash!), 'privileged password left intact');
    // One-shot: token still consumed even on refusal.
    assert.notEqual(store.resetTokens[0].used_at, null, 'token burned on refusal');
  });

  // ── not-a-customer-of-this-tenant refusal ──

  it('refuses (reset_failed) when the token user is NOT a customer of the completing tenant', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUser(store, { id: 'u1', email: 'other@b.com', password: 'old-password' });
    // Customer of a DIFFERENT tenant only.
    seedMembership(store, { userId: 'u1', tenantId: 'some-other-tenant', context: 'customer' });
    await seedResetToken(store, { userId: 'u1', plaintext: 'reset-tok' });

    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 'reset-tok', newPassword: 'brand-new-password', tenantId: TENANT.id, tenantOrigin: ORIGIN }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'reset_failed');
    const u = store.users.find(x => x.id === 'u1')!;
    assert.ok(await verifyPassword('old-password', u.password_hash!), 'password unchanged for non-customer');
  });

  // ── bad / expired / used token refusals ──

  it('refuses (reset_failed) for an unknown token', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUser(store, { id: 'u1', email: 'cust@b.com', password: 'old-password' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });

    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 'does-not-exist', newPassword: 'brand-new-password', tenantId: TENANT.id, tenantOrigin: ORIGIN }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'reset_failed');
  });

  it('refuses (reset_failed) for an expired token', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUser(store, { id: 'u1', email: 'cust@b.com', password: 'old-password' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });
    await seedResetToken(store, { userId: 'u1', plaintext: 'reset-tok', expiresAt: NOW() - 10 });

    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 'reset-tok', newPassword: 'brand-new-password', tenantId: TENANT.id, tenantOrigin: ORIGIN }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'reset_failed');
  });

  it('refuses (reset_failed) for an already-used token', async () => {
    const store = newStore();
    store.tenants.push(TENANT);
    await seedUser(store, { id: 'u1', email: 'cust@b.com', password: 'old-password' });
    seedMembership(store, { userId: 'u1', tenantId: TENANT.id, context: 'customer' });
    await seedResetToken(store, { userId: 'u1', plaintext: 'reset-tok', used: true });

    const res = await handleInternalCustomerAuth(
      makeRequest({ token: 'reset-tok', newPassword: 'brand-new-password', tenantId: TENANT.id, tenantOrigin: ORIGIN }, INTERNAL_SECRET),
      mockEnv(store),
    );
    assert.equal(res.status, 400);
    const body = await res.json() as Record<string, string>;
    assert.equal(body.error, 'reset_failed');
  });
});
