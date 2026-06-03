/**
 * Third-Party OAuth Authorize / Consent / Token — UNIT tests
 *
 * Phase 3.18 Session 6. These are TRUE unit tests: they exercise the real
 * handlers (handleOauthAuthorize, handleOauthAuthorizeDecision, handleOauthToken)
 * against an in-memory D1 mock + a real ES256 keypair generated in-process. They
 * run in CI with no staging dependency, so the security-critical assertions
 * (PKCE S256, one-shot/replay, expiry, scope-subset, client validity) are
 * actually validated rather than deferred to a deploy.
 *
 * Covered:
 *   authorize: invalid client → error page (400); valid → 200 consent; scope NOT
 *              subset → redirect with error; not-logged-in → 302 to /login?next=.
 *   decision:  Allow → 302 with code; Deny → 302 with error=access_denied.
 *   token:     valid code + PKCE → 200 + access/refresh; expired code → invalid_grant;
 *              replayed code → invalid_grant; mismatched verifier → invalid_grant;
 *              bad client secret → 401.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';

import { handleOauthAuthorize, handleOauthAuthorizeDecision } from '../src/handlers/oauthAuthorize.js';
import { handleOauthToken } from '../src/handlers/oauthToken.js';
import { hashPassword } from '../src/crypto/passwords.js';
import { hashRefreshToken } from '../src/crypto/refreshTokens.js';
import type { Env } from '../src/types.js';

// ─── In-memory D1 mock ──────────────────────────────────────
//
// Supports exactly the statements the Session-6 code path issues against AUTH_DB:
// PRAGMA, oauth_third_party_clients SELECT, oauth_authorization_codes
// INSERT/SELECT/UPDATE, refresh_tokens SELECT/INSERT, users SELECT.

interface ClientRecord {
  client_id: string;
  client_secret_hash: string;
  client_name: string;
  redirect_uris_json: string;
  allowed_scopes_json: string;
  created_at: number;
  created_by_user_id: string;
  status: string;
  contact_email: string | null;
}
interface AuthCodeRecord {
  code: string;
  client_id: string;
  user_id: string;
  granted_scopes_json: string;
  code_challenge: string;
  redirect_uri: string;
  expires_at: number;
  used_at: number | null;
}
interface RefreshRecord {
  id: string;
  user_id: string;
  token_hash: string;
  family_id: string;
  expires_at: number;
  revoked_at: string | null;
  login_iat: number;
}
interface UserRecord {
  id: string;
  email: string;
  name: string;
}

class MockDB {
  clients = new Map<string, ClientRecord>();
  codes = new Map<string, AuthCodeRecord>();
  refresh = new Map<string, RefreshRecord>(); // keyed by token_hash
  users = new Map<string, UserRecord>();

  exec(_sql: string) {
    return Promise.resolve({ count: 0, duration: 0 });
  }

  prepare(sql: string) {
    return new MockStatement(this, sql.trim());
  }
}

class MockStatement {
  private params: unknown[] = [];
  constructor(private db: MockDB, private sql: string) {}

  bind(...args: unknown[]): MockStatement {
    this.params = args;
    return this;
  }

  async first<T>(): Promise<T | null> {
    const s = this.sql;
    if (s.startsWith('SELECT * FROM oauth_third_party_clients WHERE client_id')) {
      return (this.db.clients.get(this.params[0] as string) as T) ?? null;
    }
    if (s.startsWith('SELECT client_secret_hash, status FROM oauth_third_party_clients')) {
      const c = this.db.clients.get(this.params[0] as string);
      return c ? ({ client_secret_hash: c.client_secret_hash, status: c.status } as T) : null;
    }
    if (s.startsWith('SELECT * FROM oauth_authorization_codes WHERE code')) {
      return (this.db.codes.get(this.params[0] as string) as T) ?? null;
    }
    if (s.startsWith('SELECT * FROM refresh_tokens WHERE token_hash')) {
      return (this.db.refresh.get(this.params[0] as string) as T) ?? null;
    }
    if (s.startsWith('SELECT * FROM users WHERE id')) {
      return (this.db.users.get(this.params[0] as string) as T) ?? null;
    }
    throw new Error(`MockStatement.first: unhandled SQL: ${s}`);
  }

  async run(): Promise<{ meta: { changes: number } }> {
    const s = this.sql;
    if (s.startsWith('INSERT INTO oauth_authorization_codes')) {
      const [code, client_id, user_id, granted_scopes_json, code_challenge, redirect_uri, expires_at] =
        this.params as [string, string, string, string, string, string, number];
      this.db.codes.set(code, {
        code, client_id, user_id, granted_scopes_json, code_challenge, redirect_uri,
        expires_at, used_at: null,
      });
      return { meta: { changes: 1 } };
    }
    if (s.startsWith('UPDATE oauth_authorization_codes SET used_at')) {
      const [usedAt, code] = this.params as [number, string];
      const row = this.db.codes.get(code);
      if (row && row.used_at === null) {
        row.used_at = usedAt;
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    if (s.startsWith('INSERT INTO refresh_tokens')) {
      const p = this.params as unknown[];
      const rec: RefreshRecord = {
        id: p[0] as string,
        user_id: p[1] as string,
        token_hash: p[2] as string,
        family_id: p[3] as string,
        expires_at: p[4] as number,
        revoked_at: null,
        login_iat: (p[10] as number) ?? 0,
      };
      this.db.refresh.set(rec.token_hash, rec);
      return { meta: { changes: 1 } };
    }
    if (s.startsWith('UPDATE refresh_tokens SET revoked_at')) {
      // Family/single revocation paths — not exercised by the happy-path tests.
      return { meta: { changes: 0 } };
    }
    throw new Error(`MockStatement.run: unhandled SQL: ${s}`);
  }

  async all<T>(): Promise<{ results: T[] }> {
    throw new Error(`MockStatement.all: unhandled SQL: ${this.sql}`);
  }
}

// ─── Mock env ───────────────────────────────────────────────

function makeEnv(db: MockDB): Env {
  // Real ES256 keypair → base64(PEM) as the signer expects.
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

  // Minimal KV stub — redirect validator only reads `domain:<host>` keys; our
  // test redirect_uri uses a controlled suffix (.workers.dev) so the validator
  // never needs a KV hit, but get() must exist.
  const kv = { get: async () => null } as unknown as KVNamespace;

  return {
    AUTH_DB: db as unknown as D1Database,
    TENANTS_DB: db as unknown as D1Database,
    CANONICAL_INPUTS: kv,
    TENANT_CONFIGS: kv,
    ENVIRONMENT: 'staging',
    AUTH_DOMAIN: 'https://centerpiece-auth-staging.workers.dev',
    ACCESS_TOKEN_TTL_SECONDS: '900',
    REFRESH_TOKEN_TTL_DAYS: '30',
    REFRESH_TOKEN_TTL_DAYS_REMEMBERED: '90',
    AUTH_CODE_TTL_SECONDS: '60',
    PLATFORM_TENANT_ID: 'centerpiecelab',
    JWT_PRIVATE_KEY: Buffer.from(privPem).toString('base64'),
    JWT_PUBLIC_KEY: Buffer.from(pubPem).toString('base64'),
    EMAIL_FROM: 'noreply@example.com',
    EMAIL_FROM_NAME: 'Test',
    INTERNAL_SECRET: 'test-internal-secret-0123456789',
    PLATFORM_OWNER_EMAIL_DOMAINS: 'centerpiecelab.com',
    PLATFORM_DOMAIN: 'centerpiecelab.dev',
    AUTH_ISSUER_URL: 'https://centerpiece-auth-staging.workers.dev',
  } as Env;
}

// ─── Fixtures ───────────────────────────────────────────────

const CLIENT_ID = 'client-acme-mcp';
const CLIENT_SECRET = 'a'.repeat(64);
const REDIRECT_URI = 'https://acme-bridge.workers.dev/callback';
const USER_ID = 'user-seller-1';

// PKCE verifier + S256 challenge (base64url of SHA256(verifier)).
const CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
function s256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}
const CODE_CHALLENGE = s256Challenge(CODE_VERIFIER);

async function seed(db: MockDB) {
  db.clients.set(CLIENT_ID, {
    client_id: CLIENT_ID,
    client_secret_hash: await hashPassword(CLIENT_SECRET),
    client_name: 'Acme MCP Bridge',
    redirect_uris_json: JSON.stringify([REDIRECT_URI]),
    allowed_scopes_json: JSON.stringify(['orders:read', 'orders:write', 'tenant:read']),
    created_at: 1,
    created_by_user_id: 'admin-1',
    status: 'active',
    contact_email: null,
  });
  db.users.set(USER_ID, { id: USER_ID, email: 'seller@example.com', name: 'Seller One' });
}

/** Seed a live refresh-token session for USER_ID; returns the cookie header. */
async function seedSession(db: MockDB, env: Env): Promise<string> {
  const plaintext = 'session-refresh-token-' + Math.random().toString(36).slice(2);
  const hash = await hashRefreshToken(plaintext);
  const now = Math.floor(Date.now() / 1000);
  db.refresh.set(hash, {
    id: 'rt-1',
    user_id: USER_ID,
    token_hash: hash,
    family_id: 'fam-1',
    expires_at: now + 86400,
    revoked_at: null,
    login_iat: now,
  });
  return `cp_refresh=${plaintext}`;
}

function authorizeUrl(overrides: Record<string, string | null> = {}): string {
  const params: Record<string, string> = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'orders:read',
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: 'S256',
    state: 'xyz-state-123',
  };
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null) delete params[k];
    else params[k] = v;
  }
  const u = new URL('https://auth.test/oauth/authorize');
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

// ─── Authorize ──────────────────────────────────────────────

describe('GET /oauth/authorize', () => {
  it('invalid client → 400 error page (not a redirect)', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const cookie = await seedSession(db, env);
    const res = await handleOauthAuthorize(
      new Request(authorizeUrl({ client_id: 'no-such-client' }), { headers: { Cookie: cookie } }),
      env,
    );
    assert.equal(res.status, 400);
    assert.equal(res.headers.get('Location'), null, 'must NOT redirect for invalid client');
    assert.match(res.headers.get('Content-Type') || '', /text\/html/);
  });

  it('valid request + live session → 200 consent screen', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const cookie = await seedSession(db, env);
    const res = await handleOauthAuthorize(
      new Request(authorizeUrl(), { headers: { Cookie: cookie } }),
      env,
    );
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /Authorize access/);
    assert.match(html, /Acme MCP Bridge/);
    assert.match(html, /View your orders/); // human-readable scope text
    assert.match(html, /name="request"/);   // signed request hidden field
    assert.match(html, /name="csrf"/);
  });

  it('scope NOT a subset of client allowed scopes → redirect with invalid_scope', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const cookie = await seedSession(db, env);
    const res = await handleOauthAuthorize(
      new Request(authorizeUrl({ scope: 'orders:read tenant:write' }), { headers: { Cookie: cookie } }),
      env,
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get('Location')!);
    assert.equal(loc.searchParams.get('error'), 'invalid_scope');
    assert.equal(loc.searchParams.get('state'), 'xyz-state-123');
  });

  it('missing code_challenge → redirect with invalid_request', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const cookie = await seedSession(db, env);
    const res = await handleOauthAuthorize(
      new Request(authorizeUrl({ code_challenge: null }), { headers: { Cookie: cookie } }),
      env,
    );
    assert.equal(res.status, 302);
    assert.equal(new URL(res.headers.get('Location')!).searchParams.get('error'), 'invalid_request');
  });

  it('not logged in → 302 to /login?next=<authorize url>', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const res = await handleOauthAuthorize(new Request(authorizeUrl()), env); // no cookie
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get('Location')!);
    assert.equal(loc.pathname, '/login');
    assert.ok(loc.searchParams.get('next')?.includes('/oauth/authorize'));
  });
});

// ─── Decision → Token round trip ────────────────────────────

/** Drive authorize → extract signed request + csrf from the consent HTML. */
async function getConsent(db: MockDB, env: Env, cookie: string) {
  const res = await handleOauthAuthorize(new Request(authorizeUrl(), { headers: { Cookie: cookie } }), env);
  const html = await res.text();
  const request = /name="request" value="([^"]+)"/.exec(html)![1];
  const csrf = /name="csrf" value="([^"]+)"/.exec(html)![1];
  return { request, csrf };
}

function decisionRequest(body: Record<string, string>, cookie: string): Request {
  return new Request('https://auth.test/oauth/authorize/decision', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie },
    body: new URLSearchParams(body).toString(),
  });
}

describe('POST /oauth/authorize/decision', () => {
  it('Deny → 302 redirect with error=access_denied', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const cookie = await seedSession(db, env);
    const { request, csrf } = await getConsent(db, env, cookie);
    const res = await handleOauthAuthorizeDecision(
      decisionRequest({ request, csrf, decision: 'deny' }, cookie),
      env,
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get('Location')!);
    assert.equal(loc.searchParams.get('error'), 'access_denied');
    assert.equal(loc.searchParams.get('state'), 'xyz-state-123');
  });

  it('Allow → 302 redirect with code + state', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const cookie = await seedSession(db, env);
    const { request, csrf } = await getConsent(db, env, cookie);
    const res = await handleOauthAuthorizeDecision(
      decisionRequest({ request, csrf, decision: 'allow' }, cookie),
      env,
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get('Location')!);
    const code = loc.searchParams.get('code');
    assert.ok(code && code.length === 64, 'code must be 32-byte hex');
    assert.equal(loc.searchParams.get('state'), 'xyz-state-123');
    assert.ok(db.codes.has(code!), 'code persisted to D1');
  });

  it('tampered CSRF → 403 (no code minted)', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const cookie = await seedSession(db, env);
    const { request } = await getConsent(db, env, cookie);
    const res = await handleOauthAuthorizeDecision(
      decisionRequest({ request, csrf: 'wrong-csrf', decision: 'allow' }, cookie),
      env,
    );
    assert.equal(res.status, 403);
    assert.equal(db.codes.size, 0);
  });
});

// ─── Token ──────────────────────────────────────────────────

function tokenRequest(body: Record<string, string>, basic = true): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (basic) {
    headers.Authorization = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  }
  return new Request('https://auth.test/oauth/token', {
    method: 'POST',
    headers,
    body: new URLSearchParams(body).toString(),
  });
}

/** Authorize → Allow → returns the minted code. */
async function mintCode(db: MockDB, env: Env): Promise<string> {
  const cookie = await seedSession(db, env);
  const { request, csrf } = await getConsent(db, env, cookie);
  const res = await handleOauthAuthorizeDecision(
    decisionRequest({ request, csrf, decision: 'allow' }, cookie),
    env,
  );
  return new URL(res.headers.get('Location')!).searchParams.get('code')!;
}

describe('POST /oauth/token (authorization_code + PKCE)', () => {
  it('valid code + correct verifier → 200 with access + refresh tokens and act_as claim', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const code = await mintCode(db, env);

    const res = await handleOauthToken(
      tokenRequest({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: CODE_VERIFIER,
      }),
      env,
    );
    assert.equal(res.status, 200, `body: ${await res.clone().text()}`);
    const body = (await res.json()) as Record<string, unknown>;
    assert.ok(body.access_token, 'access_token present');
    assert.equal(body.token_type, 'Bearer');
    assert.equal(body.expires_in, 900);
    assert.ok(body.refresh_token, 'refresh_token present');
    assert.equal(body.scope, 'orders:read');

    // act_as claim embedded in the access token.
    const payload = JSON.parse(
      Buffer.from((body.access_token as string).split('.')[1], 'base64url').toString(),
    );
    assert.deepEqual(payload.act_as, { client_id: CLIENT_ID });
    assert.equal(payload.aud, 'storefront');
    assert.equal(payload.sub, USER_ID);
  });

  it('replayed code → 400 invalid_grant (one-shot)', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const code = await mintCode(db, env);

    const first = await handleOauthToken(
      tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: CODE_VERIFIER }),
      env,
    );
    assert.equal(first.status, 200);

    const replay = await handleOauthToken(
      tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: CODE_VERIFIER }),
      env,
    );
    assert.equal(replay.status, 400);
    assert.equal(((await replay.json()) as Record<string, string>).error, 'invalid_grant');
  });

  it('mismatched code_verifier → 400 invalid_grant (PKCE)', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const code = await mintCode(db, env);

    const res = await handleOauthToken(
      tokenRequest({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: 'totally-wrong-verifier-value-that-does-not-match',
      }),
      env,
    );
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as Record<string, string>).error, 'invalid_grant');
  });

  it('expired code → 400 invalid_grant', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const code = await mintCode(db, env);
    // Force expiry in the persisted row.
    db.codes.get(code)!.expires_at = Math.floor(Date.now() / 1000) - 10;

    const res = await handleOauthToken(
      tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: CODE_VERIFIER }),
      env,
    );
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as Record<string, string>).error, 'invalid_grant');
  });

  it('mismatched redirect_uri → 400 invalid_grant', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const code = await mintCode(db, env);

    const res = await handleOauthToken(
      tokenRequest({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://acme-bridge.workers.dev/other',
        code_verifier: CODE_VERIFIER,
      }),
      env,
    );
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as Record<string, string>).error, 'invalid_grant');
  });

  it('bad client secret → 401 invalid_client', async () => {
    const db = new MockDB();
    const env = makeEnv(db);
    await seed(db);
    const code = await mintCode(db, env);

    const badReq = new Request('https://auth.test/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: 'Basic ' + Buffer.from(`${CLIENT_ID}:wrong-secret`).toString('base64'),
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: CODE_VERIFIER,
      }).toString(),
    });
    const res = await handleOauthToken(badReq, env);
    assert.equal(res.status, 401);
    assert.equal(((await res.json()) as Record<string, string>).error, 'invalid_client');
  });
});
