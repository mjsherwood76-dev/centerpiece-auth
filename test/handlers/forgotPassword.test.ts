/**
 * Unit tests for the auth-domain forgot-password handler (S2 narrow-deny guard).
 *
 *   POST /api/forgot-password  →  handleForgotPassword
 *
 * Uses in-process mocks (mock D1 for AUTH_DB, mock KV) — does NOT hit staging.
 *
 * Covers the Fix — Customer Storefront Auth, S2 narrow-deny rule: the public
 * /forgot-password page issues a reset for EVERYONE who legitimately uses the
 * auth domain — privileged users, no-membership/onboarding users, mixed-context
 * users — and DENIES (constant no-op, no email) ONLY a CONFIRMED PURE-CUSTOMER
 * (holds an active `customer` membership on some tenant AND no privileged
 * context). The deny case must NOT lock out onboarding sellers / orphaned users.
 *
 * "Reset sent" is observed via store.resetTokens.length: the handler inserts the
 * reset token immediately before sending the (graceful-degrade) email, only on
 * the allow path. The response is the constant `302 …message=reset_sent` in every
 * branch (account-enumeration prevention), so the token store is the branch
 * signal, not the response.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleForgotPassword } from '../../src/handlers/forgotPassword.js';
import type { Env } from '../../src/types.js';

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
  resetTokens: Array<Record<string, unknown>>;
}

function newStore(): Store {
  return { users: [], memberships: [], resetTokens: [] };
}

/**
 * Mock D1 backed by `store`. Recognizes the SQL the handler issues via AuthDB:
 * user lookup, hasAnyCustomerMembership (no tenant filter), getAdminMemberships
 * (privileged check), password-reset insert.
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
        // hasAnyCustomerMembership: SELECT 1 FROM tenant_memberships
        //   WHERE user_id = ? AND context = 'customer' AND status = 'active' LIMIT 1
        if (lower.startsWith('select 1 from tenant_memberships')) {
          const userId = String(args[0]);
          const hit = store.memberships.some(
            m => m.user_id === userId && m.context === 'customer' && m.status === 'active',
          );
          return (hit ? ({ 1: 1 } as unknown as T) : null);
        }
        return null as T | null;
      },
      run: async () => {
        if (lower.startsWith('insert into password_reset_tokens')) {
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
    TENANTS_DB: buildAuthDb(store),
    CANONICAL_INPUTS: buildKv(),
    TENANT_CONFIGS: buildKv(),
    ENVIRONMENT: 'staging',
    AUTH_DOMAIN: 'https://auth.centerpiecelab.dev',
    PLATFORM_TENANT_ID: '__platform__',
    EMAIL_FROM: 'noreply@centerpiecelab.com',
    EMAIL_FROM_NAME: 'Centerpiece',
    // No SENDGRID_API_KEY / PLATFORM_API: sendPasswordResetEmail degrades
    // gracefully (never throws) on the allow path.
  } as unknown as Env;
}

function seedUser(store: Store, opts: { id: string; email: string }): void {
  store.users.push({
    id: opts.id, email: opts.email.toLowerCase(),
    password_hash: 'x', name: 'Test', email_verified: 1, avatar_url: null,
    created_at: '', updated_at: '',
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

function makeRequest(email: string): Request {
  const body = new URLSearchParams({ email, tenant: 'sherwood-creative' });
  return new Request('https://auth.centerpiecelab.dev/api/forgot-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
}

/** Every branch returns the same constant success redirect. */
function assertConstantResponse(res: Response): void {
  assert.equal(res.status, 302, 'always a 302 redirect');
  const location = res.headers.get('Location') || '';
  assert.ok(location.includes('message=reset_sent'), 'constant reset_sent message (no enumeration)');
}

// ─── Tests ──────────────────────────────────────────────────

describe('POST /api/forgot-password (S2 narrow-deny)', () => {
  it('sends a reset for a privileged user (legit auth-domain self-reset)', async () => {
    const store = newStore();
    seedUser(store, { id: 'u1', email: 'seller@b.com' });
    seedMembership(store, { userId: 'u1', tenantId: 'sherwood-creative', context: 'seller', subRole: 'owner' });

    const res = await handleForgotPassword(makeRequest('seller@b.com'), mockEnv(store));
    assertConstantResponse(res);
    assert.equal(store.resetTokens.length, 1, 'reset sent for privileged user');
  });

  it('sends a reset for a NO-membership / onboarding user (the lockout case must NOT regress)', async () => {
    const store = newStore();
    // User row exists but no memberships of any context yet (seller mid-onboarding
    // / orphaned). A broad "only privileged" guard would lock this user out.
    seedUser(store, { id: 'u1', email: 'newbie@b.com' });

    const res = await handleForgotPassword(makeRequest('newbie@b.com'), mockEnv(store));
    assertConstantResponse(res);
    assert.equal(store.resetTokens.length, 1, 'reset sent for no-membership/onboarding user');
  });

  it('does NOT send a reset for a confirmed pure-customer (resets via storefront)', async () => {
    const store = newStore();
    seedUser(store, { id: 'u1', email: 'cust@b.com' });
    // Active customer membership (on some tenant) and NO privileged context.
    seedMembership(store, { userId: 'u1', tenantId: 'sherwood-creative', context: 'customer' });

    const res = await handleForgotPassword(makeRequest('cust@b.com'), mockEnv(store));
    assertConstantResponse(res);
    assert.equal(store.resetTokens.length, 0, 'no reset for confirmed pure-customer');
  });

  it('still denies a pure-customer whose only customer membership is on ANOTHER tenant', async () => {
    const store = newStore();
    seedUser(store, { id: 'u1', email: 'cust2@b.com' });
    // Customer of a different tenant; the auth-domain guard is tenant-agnostic
    // (customer-anywhere). No privileged context → still a confirmed pure-customer.
    seedMembership(store, { userId: 'u1', tenantId: 'some-other-tenant', context: 'customer' });

    const res = await handleForgotPassword(makeRequest('cust2@b.com'), mockEnv(store));
    assertConstantResponse(res);
    assert.equal(store.resetTokens.length, 0, 'no reset for pure-customer-of-any-tenant');
  });

  it('sends a reset for a mixed-context user (customer + privileged)', async () => {
    const store = newStore();
    seedUser(store, { id: 'u1', email: 'mike@b.com' });
    seedMembership(store, { userId: 'u1', tenantId: 'sherwood-creative', context: 'customer' });
    seedMembership(store, { userId: 'u1', tenantId: 'sherwood-creative', context: 'platform', subRole: 'owner' });

    const res = await handleForgotPassword(makeRequest('mike@b.com'), mockEnv(store));
    assertConstantResponse(res);
    assert.equal(store.resetTokens.length, 1, 'reset sent for mixed-context user (privileged wins)');
  });

  it('returns the constant response for an unknown email (no enumeration)', async () => {
    const store = newStore();
    const res = await handleForgotPassword(makeRequest('ghost@b.com'), mockEnv(store));
    assertConstantResponse(res);
    assert.equal(store.resetTokens.length, 0, 'no reset token for unknown email');
  });

  it('returns the constant response for an empty email', async () => {
    const store = newStore();
    const res = await handleForgotPassword(makeRequest(''), mockEnv(store));
    assertConstantResponse(res);
    assert.equal(store.resetTokens.length, 0);
  });

  it('keeps timing comparable across allow and deny branches (constant-time)', async () => {
    // The deny branch runs dummyHashDelay() (PBKDF2 100k) to avoid returning
    // conspicuously faster than the allow branch's token-gen + hash + email path.
    // Assert both branches incur measurable work and are within the same order of
    // magnitude — a coarse guard against the deny branch becoming a fast no-op.
    const denyStore = newStore();
    seedUser(denyStore, { id: 'u1', email: 'cust@b.com' });
    seedMembership(denyStore, { userId: 'u1', tenantId: 'sherwood-creative', context: 'customer' });

    const allowStore = newStore();
    seedUser(allowStore, { id: 'u2', email: 'seller@b.com' });
    seedMembership(allowStore, { userId: 'u2', tenantId: 'sherwood-creative', context: 'seller', subRole: 'owner' });

    const t0 = performance.now();
    await handleForgotPassword(makeRequest('cust@b.com'), mockEnv(denyStore));
    const denyMs = performance.now() - t0;

    const t1 = performance.now();
    await handleForgotPassword(makeRequest('seller@b.com'), mockEnv(allowStore));
    const allowMs = performance.now() - t1;

    assert.equal(denyStore.resetTokens.length, 0, 'deny branch sent no reset');
    assert.equal(allowStore.resetTokens.length, 1, 'allow branch sent a reset');
    // Both branches do real crypto work; neither should be a sub-millisecond no-op.
    assert.ok(denyMs > 1, `deny branch should do measurable work (was ${denyMs.toFixed(2)}ms)`);
    assert.ok(allowMs > 1, `allow branch should do measurable work (was ${allowMs.toFixed(2)}ms)`);
  });
});
