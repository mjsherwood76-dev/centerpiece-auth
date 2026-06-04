/**
 * Unit tests for Phase 3.25 email-verification flow + email_verified JWT claim.
 *
 * Pure in-process tests — no network, no staging. Covers:
 * - buildCustomerJwtPayload threads `email_verified` (present/absent)
 * - buildEmailVerificationEmail produces a branded link + expiry copy
 * - loadTenantGating reads the gated posture from a mock TENANT_CONFIGS KV
 * - GET /verify-email handler: success sets email_verified, reused/expired/
 *   missing tokens fail closed and never set it
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildCustomerJwtPayload, sha256Hex } from '../../src/crypto/jwt.js';
import { buildEmailVerificationEmail } from '../../src/email/templates.js';
import { loadTenantGating } from '../../src/security/tenantGating.js';
import { handleVerifyEmail } from '../../src/handlers/verifyEmail.js';
import type { Env } from '../../src/types.js';

const IDENTITY = {
  userId: 'user-1',
  email: 'someone@valhallan.com',
  name: 'Some One',
  iss: 'https://auth.centerpiecelab.com',
};

// ─── JWT claim ──────────────────────────────────────────────

describe('buildCustomerJwtPayload email_verified', () => {
  it('sets email_verified=true when emailVerified true', () => {
    const p = buildCustomerJwtPayload({ ...IDENTITY, emailVerified: true });
    assert.equal(p.email_verified, true);
    assert.equal(p.aud, 'storefront');
  });

  it('sets email_verified=false when emailVerified false', () => {
    const p = buildCustomerJwtPayload({ ...IDENTITY, emailVerified: false });
    assert.equal(p.email_verified, false);
  });

  it('omits email_verified when not provided (back-compat)', () => {
    const p = buildCustomerJwtPayload(IDENTITY);
    assert.equal(p.email_verified, undefined);
  });
});

// ─── Email template ─────────────────────────────────────────

describe('buildEmailVerificationEmail', () => {
  const branding = {
    storeName: 'Valhallan',
    logoUrl: null,
    primaryColor: '#2563eb',
    backgroundColor: '#ffffff',
  };

  it('includes the verification link and expiry', () => {
    const url = 'https://auth.centerpiecelab.com/verify-email?token=abc123';
    const email = buildEmailVerificationEmail({ branding, verificationUrl: url, expiresInMinutes: 60 });
    assert.ok(email.html.includes(url), 'html contains link');
    assert.ok(email.text.includes(url), 'text contains link');
    assert.ok(email.html.includes('60 minutes'), 'html mentions expiry');
    assert.ok(email.subject.includes('Valhallan'), 'subject branded');
  });
});

// ─── Tenant gating lookup ───────────────────────────────────

function kvWith(record: unknown): KVNamespace {
  return {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async get(_key: string, _type?: string) {
      return record as never;
    },
  } as unknown as KVNamespace;
}

describe('loadTenantGating', () => {
  it('returns public for null tenant', async () => {
    const env = { TENANT_CONFIGS: kvWith(null) } as unknown as Env;
    const g = await loadTenantGating(env, null);
    assert.equal(g.gated, false);
    assert.equal(g.policy, 'public');
  });

  it('reads domain-allowlist + allowedEmailDomains from a wrapped config', async () => {
    const env = {
      TENANT_CONFIGS: kvWith({
        config: {
          defaultAccessRequirement: { policy: 'domain-allowlist' },
          allowedEmailDomains: ['Valhallan.com', 'xpleague.com'],
        },
      }),
    } as unknown as Env;
    const g = await loadTenantGating(env, 'valhallan');
    assert.equal(g.gated, true);
    assert.equal(g.policy, 'domain-allowlist');
    assert.deepEqual(g.allowedEmailDomains, ['valhallan.com', 'xpleague.com']);
  });

  it('treats unknown/public policy as not gated', async () => {
    const env = {
      TENANT_CONFIGS: kvWith({ config: { defaultAccessRequirement: { policy: 'public' } } }),
    } as unknown as Env;
    const g = await loadTenantGating(env, 'public-tenant');
    assert.equal(g.gated, false);
  });

  it('fails soft to public on KV throw', async () => {
    const env = {
      TENANT_CONFIGS: { async get() { throw new Error('kv down'); } },
    } as unknown as Env;
    const g = await loadTenantGating(env, 'x');
    assert.equal(g.gated, false);
  });
});

// ─── verify-email handler ───────────────────────────────────

interface TokenRow { user_id: string; expires_at: number; consumed_at: number | null; token_hash: string; }

/**
 * Minimal mock AUTH_DB supporting only the three statements verifyEmail uses:
 *  - SELECT ... FROM email_verification_tokens WHERE token_hash = ? AND consumed_at IS NULL
 *  - UPDATE email_verification_tokens SET consumed_at = ? WHERE token_hash = ?
 *  - UPDATE users SET email_verified = 1 WHERE id = ?
 * Plus PRAGMA (exec).
 */
function mockDb(tokens: TokenRow[], verified: Set<string>): D1Database {
  return {
    async exec() { return { count: 0, duration: 0 } as never; },
    prepare(sql: string) {
      let bound: unknown[] = [];
      const stmt = {
        bind(...args: unknown[]) { bound = args; return stmt; },
        async first<T>() {
          if (sql.includes('FROM email_verification_tokens')) {
            const hash = bound[0] as string;
            const row = tokens.find(t => t.token_hash === hash && t.consumed_at === null);
            return (row ? { user_id: row.user_id, expires_at: row.expires_at } : null) as T;
          }
          return null as T;
        },
        async run() {
          if (sql.startsWith('UPDATE email_verification_tokens')) {
            const hash = bound[1] as string;
            const row = tokens.find(t => t.token_hash === hash);
            if (row) row.consumed_at = bound[0] as number;
          } else if (sql.startsWith('UPDATE users SET email_verified')) {
            verified.add(bound[0] as string);
          }
          return { success: true } as never;
        },
      };
      return stmt as never;
    },
  } as unknown as D1Database;
}

function verifyEnv(db: D1Database): Env {
  return {
    AUTH_DB: db,
    TENANT_CONFIGS: kvWith(null),
    CANONICAL_INPUTS: kvWith(null),
    AUTH_DOMAIN: 'https://auth.centerpiecelab.com',
    PLATFORM_DOMAIN: 'centerpiecelab.com',
    ENVIRONMENT: 'staging',
  } as unknown as Env;
}

describe('GET /verify-email', () => {
  const now = () => Math.floor(Date.now() / 1000);

  it('verifies on a valid unconsumed token', async () => {
    const hash = await sha256Hex('good-token');
    const tokens: TokenRow[] = [{ user_id: 'u1', expires_at: now() + 600, consumed_at: null, token_hash: hash }];
    const verified = new Set<string>();
    const env = verifyEnv(mockDb(tokens, verified));

    const res = await handleVerifyEmail(
      new Request('https://auth.centerpiecelab.com/verify-email?token=good-token&tenant=valhallan'),
      env,
    );
    assert.equal(res.status, 200);
    assert.ok(verified.has('u1'), 'email_verified set');
    assert.ok(tokens[0].consumed_at !== null, 'token consumed');
  });

  it('fails closed on a reused (already consumed) token', async () => {
    const hash = await sha256Hex('used-token');
    const tokens: TokenRow[] = [{ user_id: 'u1', expires_at: now() + 600, consumed_at: now() - 5, token_hash: hash }];
    const verified = new Set<string>();
    const env = verifyEnv(mockDb(tokens, verified));

    const res = await handleVerifyEmail(
      new Request('https://auth.centerpiecelab.com/verify-email?token=used-token'),
      env,
    );
    assert.equal(res.status, 400);
    assert.equal(verified.has('u1'), false);
  });

  it('fails closed on an expired token', async () => {
    const hash = await sha256Hex('old-token');
    const tokens: TokenRow[] = [{ user_id: 'u1', expires_at: now() - 10, consumed_at: null, token_hash: hash }];
    const verified = new Set<string>();
    const env = verifyEnv(mockDb(tokens, verified));

    const res = await handleVerifyEmail(
      new Request('https://auth.centerpiecelab.com/verify-email?token=old-token'),
      env,
    );
    assert.equal(res.status, 400);
    assert.equal(verified.has('u1'), false);
  });

  it('fails closed on a missing token param', async () => {
    const env = verifyEnv(mockDb([], new Set()));
    const res = await handleVerifyEmail(
      new Request('https://auth.centerpiecelab.com/verify-email'),
      env,
    );
    assert.equal(res.status, 400);
  });
});
