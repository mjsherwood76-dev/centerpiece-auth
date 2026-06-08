/**
 * Unit tests for the public accept-invite flow (Fix_Team_Invites S4) — HIGH RISK.
 *
 * Runs handleAcceptInvitePage (GET) + handleAcceptInvite (POST) end-to-end
 * against an in-memory better-sqlite3 DB (real migrations) + mock Env (null KVs,
 * breach-check disabled), fully offline. Asserts the security-critical
 * invariants: single-use/replay, expiry, email binding, wrong-password handling,
 * platform domain re-assertion, membership creation, session + non-PKCE admin
 * code issuance, and the server-derived hub redirect.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { handleAcceptInvitePage, handleAcceptInvite } from '../../src/handlers/acceptInvite.js';
import { hashInviteToken } from '../../src/crypto/inviteToken.js';
import { hashPassword } from '../../src/crypto/passwords.js';
import type { Env } from '../../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(__dirname, '../../migrations');

function buildSchemaDb(): Database.Database {
  const db = new Database(':memory:');
  for (const f of readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort()) {
    try { db.exec(readFileSync(join(migrationsDir, f), 'utf8')); } catch { /* see schema test */ }
  }
  return db;
}

function d1(db: Database.Database): D1Database {
  return {
    prepare(sql: string) {
      const stmt = db.prepare(sql);
      const make = (args: unknown[]) => ({
        async first<T = unknown>(): Promise<T | null> { return (stmt.get(...(args as [])) as T) ?? null; },
        async all<T = unknown>(): Promise<{ results: T[] }> { return { results: stmt.all(...(args as [])) as T[] }; },
        async run() { const r = stmt.run(...(args as [])); return { success: true, meta: { changes: r.changes } }; },
        bind(...a: unknown[]) { return make(a); },
      });
      return make([]) as unknown as D1PreparedStatement;
    },
    async exec(sql: string) { db.exec(sql); return { count: 0, duration: 0 }; },
  } as unknown as D1Database;
}

/** KV that always misses → loadTenantBranding falls back to defaults. */
const nullKv = { async get() { return null; } } as unknown as KVNamespace;

function makeEnv(rawDb: Database.Database, environment = 'staging'): Env {
  return {
    AUTH_DB: d1(rawDb),
    TENANT_CONFIGS: nullKv,
    CANONICAL_INPUTS: nullKv,
    ENVIRONMENT: environment,
    AUTH_DOMAIN: 'https://auth.centerpiecelab.dev',
    PLATFORM_DOMAIN: 'centerpiecelab.dev',
    PLATFORM_OWNER_EMAIL_DOMAINS: 'centerpiecelab.com,centerpiecelab.dev',
    REFRESH_TOKEN_TTL_DAYS: '30',
    AUTH_CODE_TTL_SECONDS: '60',
    PASSWORD_BREACH_CHECK_ENABLED: 'false',
  } as unknown as Env;
}

const TENANT = 'tenant:acme';
const INVITER = 'user-inviter-1';

interface SeedInvite {
  id?: string;
  email: string;
  tenantId?: string;
  context?: 'seller' | 'supplier' | 'platform';
  subRole?: string;
  token: string;
  expiresOffset?: string;   // SQLite datetime modifier, e.g. '+7 days' or '-1 days'
  acceptedAt?: string | null;
}

async function seedInvite(rawDb: Database.Database, opts: SeedInvite): Promise<string> {
  const id = opts.id ?? `inv-${Math.random().toString(36).slice(2)}`;
  const tokenHash = await hashInviteToken(opts.token);
  rawDb.prepare(
    `INSERT INTO tenant_invites (id,email,tenant_id,context,sub_role,token_hash,invited_by,created_at,expires_at,accepted_at)
     VALUES (?,?,?,?,?,?,?,datetime('now'),datetime('now',?),?)`
  ).run(
    id, opts.email.toLowerCase(), opts.tenantId ?? TENANT, opts.context ?? 'seller',
    opts.subRole ?? 'manager', tokenHash, INVITER, opts.expiresOffset ?? '+7 days',
    opts.acceptedAt ?? null,
  );
  return id;
}

async function seedUser(rawDb: Database.Database, email: string, password: string, id = 'user-existing-1'): Promise<void> {
  const hash = await hashPassword(password);
  rawDb.prepare(
    `INSERT OR IGNORE INTO users (id, email, email_verified, password_hash, name) VALUES (?, ?, 1, ?, 'Existing')`
  ).run(id, email.toLowerCase(), hash);
}

function getReq(token: string): Request {
  return new Request(`https://auth.centerpiecelab.dev/accept-invite?token=${encodeURIComponent(token)}`);
}

function postReq(fields: Record<string, string>): Request {
  return new Request('https://auth.centerpiecelab.dev/accept-invite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  });
}

describe('accept-invite GET page', () => {
  let rawDb: Database.Database;
  let env: Env;
  before(() => { rawDb = buildSchemaDb(); });
  after(() => rawDb.close());
  beforeEach(() => { rawDb.exec('PRAGMA foreign_keys = OFF; DELETE FROM tenant_invites; DELETE FROM tenant_memberships; DELETE FROM refresh_tokens; DELETE FROM auth_codes; DELETE FROM users; PRAGMA foreign_keys = ON;'); env = makeEnv(rawDb); });

  it('renders a registration form for a new email (email locked)', async () => {
    await seedInvite(rawDb, { email: 'newbie@acme.com', token: 'tok-new' });
    const res = await handleAcceptInvitePage(getReq('tok-new'), env);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /Accept your invitation/);
    assert.match(html, /Accept &amp; create account/);
    assert.match(html, /value="newbie@acme\.com"/);
    assert.match(html, /readonly/);
  });

  it('renders a sign-in form for an existing account', async () => {
    await seedUser(rawDb, 'member@acme.com', 'Sup3rPass!');
    await seedInvite(rawDb, { email: 'member@acme.com', token: 'tok-exist' });
    const res = await handleAcceptInvitePage(getReq('tok-exist'), env);
    const html = await res.text();
    assert.match(html, /Sign in &amp; accept/);
    assert.match(html, /value="member@acme\.com"/);
  });

  it('renders an error page for an unknown token', async () => {
    const res = await handleAcceptInvitePage(getReq('does-not-exist'), env);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Invitation unavailable/);
  });

  it('renders an error page for an expired invite', async () => {
    await seedInvite(rawDb, { email: 'late@acme.com', token: 'tok-exp', expiresOffset: '-1 days' });
    const res = await handleAcceptInvitePage(getReq('tok-exp'), env);
    assert.match(await res.text(), /expired/i);
  });

  it('renders an error page for an already-accepted invite', async () => {
    await seedInvite(rawDb, { email: 'done@acme.com', token: 'tok-acc', acceptedAt: '2026-01-01 00:00:00' });
    const res = await handleAcceptInvitePage(getReq('tok-acc'), env);
    assert.match(await res.text(), /already been used/i);
  });
});

describe('accept-invite POST — new account', () => {
  let rawDb: Database.Database;
  let env: Env;
  before(() => { rawDb = buildSchemaDb(); });
  after(() => rawDb.close());
  beforeEach(() => { rawDb.exec('PRAGMA foreign_keys = OFF; DELETE FROM tenant_invites; DELETE FROM tenant_memberships; DELETE FROM refresh_tokens; DELETE FROM auth_codes; DELETE FROM users; PRAGMA foreign_keys = ON;'); env = makeEnv(rawDb); });

  it('happy path: creates user + active membership, marks accepted, 302 to hub callback with cp_refresh + non-PKCE admin code', async () => {
    await seedInvite(rawDb, { id: 'inv-h', email: 'fresh@acme.com', context: 'seller', subRole: 'designer', token: 'tok-happy' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-happy', name: 'Fresh Hire', password: 'Sup3rPass!', confirmPassword: 'Sup3rPass!' }), env);

    assert.equal(res.status, 302);
    const loc = res.headers.get('Location')!;
    assert.ok(loc.startsWith('https://hub.centerpiecelab.dev/auth/callback?code='), `redirect to hub callback: ${loc}`);
    assert.match(loc, /returnTo=%2F(&|$)/, 'seller → hub root');
    assert.match(res.headers.get('Set-Cookie') || '', /cp_refresh=/);

    // user created + email_verified
    const user = rawDb.prepare('SELECT id, email_verified FROM users WHERE email = ?').get('fresh@acme.com') as { id: string; email_verified: number };
    assert.ok(user, 'user created');
    assert.equal(user.email_verified, 1, 'accepting proves mailbox control');

    // active membership for the invite tuple
    const mem = rawDb.prepare('SELECT context, sub_role, status FROM tenant_memberships WHERE user_id = ? AND tenant_id = ?').get(user.id, TENANT) as { context: string; sub_role: string; status: string };
    assert.deepEqual([mem.context, mem.sub_role, mem.status], ['seller', 'designer', 'active']);

    // invite marked accepted (single-use)
    const inv = rawDb.prepare('SELECT accepted_at FROM tenant_invites WHERE id = ?').get('inv-h') as { accepted_at: string | null };
    assert.ok(inv.accepted_at, 'invite consumed');

    // a NON-PKCE admin auth code was issued
    const code = rawDb.prepare('SELECT aud, code_challenge, redirect_origin FROM auth_codes WHERE user_id = ?').get(user.id) as { aud: string; code_challenge: string | null; redirect_origin: string };
    assert.equal(code.aud, 'admin');
    assert.equal(code.code_challenge, null, 'non-PKCE code (silent-refresh shape)');
    assert.equal(code.redirect_origin, 'https://hub.centerpiecelab.dev');
  });

  it('platform invite → returnTo=/platform and __platform__ membership', async () => {
    await seedInvite(rawDb, { id: 'inv-p', email: 'staffer@centerpiecelab.com', tenantId: '__platform__', context: 'platform', subRole: 'support', token: 'tok-plat' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-plat', name: 'Staffer', password: 'Sup3rPass!', confirmPassword: 'Sup3rPass!' }), env);
    assert.equal(res.status, 302);
    assert.match(res.headers.get('Location')!, /returnTo=%2Fplatform/);
    const user = rawDb.prepare('SELECT id FROM users WHERE email = ?').get('staffer@centerpiecelab.com') as { id: string };
    const mem = rawDb.prepare('SELECT context, sub_role FROM tenant_memberships WHERE user_id = ? AND tenant_id = ?').get(user.id, '__platform__') as { context: string; sub_role: string };
    assert.deepEqual([mem.context, mem.sub_role], ['platform', 'support']);
  });

  it('rejects a weak password (no user created, invite not consumed)', async () => {
    await seedInvite(rawDb, { id: 'inv-w', email: 'weak@acme.com', token: 'tok-weak' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-weak', name: 'X', password: 'short', confirmPassword: 'short' }), env);
    assert.equal(res.status, 302);
    assert.match(res.headers.get('Location')!, /error=password_weak/);
    const userCount = rawDb.prepare('SELECT COUNT(*) c FROM users').get() as { c: number };
    assert.equal(userCount.c, 0, 'no user created on weak password');
    const inv = rawDb.prepare('SELECT accepted_at FROM tenant_invites WHERE id = ?').get('inv-w') as { accepted_at: string | null };
    assert.equal(inv.accepted_at, null, 'invite NOT consumed on validation failure');
  });

  it('rejects a password mismatch', async () => {
    await seedInvite(rawDb, { email: 'mm@acme.com', token: 'tok-mm' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-mm', name: 'X', password: 'Sup3rPass!', confirmPassword: 'Different1!' }), env);
    assert.match(res.headers.get('Location')!, /error=password_mismatch/);
  });

  it('email binding: a forged form email is IGNORED — the account uses the invite email', async () => {
    await seedInvite(rawDb, { email: 'real@acme.com', token: 'tok-bind' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-bind', email: 'attacker@evil.com', name: 'X', password: 'Sup3rPass!', confirmPassword: 'Sup3rPass!' }), env);
    assert.equal(res.status, 302);
    assert.ok(rawDb.prepare('SELECT 1 FROM users WHERE email = ?').get('real@acme.com'), 'invite email used');
    const evil = rawDb.prepare('SELECT COUNT(*) c FROM users WHERE email = ?').get('attacker@evil.com') as { c: number };
    assert.equal(evil.c, 0, 'forged email never created');
  });
});

describe('accept-invite POST — existing account + replay/expiry', () => {
  let rawDb: Database.Database;
  let env: Env;
  before(() => { rawDb = buildSchemaDb(); });
  after(() => rawDb.close());
  beforeEach(() => { rawDb.exec('PRAGMA foreign_keys = OFF; DELETE FROM tenant_invites; DELETE FROM tenant_memberships; DELETE FROM refresh_tokens; DELETE FROM auth_codes; DELETE FROM users; PRAGMA foreign_keys = ON;'); env = makeEnv(rawDb); });

  it('existing account: correct password → membership + 302', async () => {
    await seedUser(rawDb, 'has@acme.com', 'Right1Pass!', 'user-has-1');
    await seedInvite(rawDb, { id: 'inv-e', email: 'has@acme.com', subRole: 'analyst', token: 'tok-e' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-e', password: 'Right1Pass!' }), env);
    assert.equal(res.status, 302);
    assert.ok(res.headers.get('Location')!.includes('/auth/callback?code='));
    const mem = rawDb.prepare('SELECT sub_role, status FROM tenant_memberships WHERE user_id = ?').get('user-has-1') as { sub_role: string; status: string };
    assert.deepEqual([mem.sub_role, mem.status], ['analyst', 'active']);
  });

  it('existing account: wrong password → generic invalid_credentials, invite NOT consumed', async () => {
    await seedUser(rawDb, 'wp@acme.com', 'Right1Pass!', 'user-wp-1');
    await seedInvite(rawDb, { id: 'inv-wp', email: 'wp@acme.com', token: 'tok-wp' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-wp', password: 'WRONGpass1!' }), env);
    assert.match(res.headers.get('Location')!, /error=invalid_credentials/);
    const inv = rawDb.prepare('SELECT accepted_at FROM tenant_invites WHERE id = ?').get('inv-wp') as { accepted_at: string | null };
    assert.equal(inv.accepted_at, null);
    assert.equal((rawDb.prepare('SELECT COUNT(*) c FROM tenant_memberships').get() as { c: number }).c, 0);
  });

  it('replay: a second accept of the same token is rejected (single-use)', async () => {
    await seedInvite(rawDb, { id: 'inv-r', email: 'once@acme.com', token: 'tok-r' });
    const first = await handleAcceptInvite(postReq({ token: 'tok-r', name: 'Once', password: 'Sup3rPass!', confirmPassword: 'Sup3rPass!' }), env);
    assert.equal(first.status, 302);
    const second = await handleAcceptInvite(postReq({ token: 'tok-r', name: 'Once', password: 'Sup3rPass!', confirmPassword: 'Sup3rPass!' }), env);
    assert.equal(second.status, 200);
    assert.match(await second.text(), /already been used/i);
    // exactly one membership
    assert.equal((rawDb.prepare('SELECT COUNT(*) c FROM tenant_memberships').get() as { c: number }).c, 1, 'no double-grant on replay');
  });

  it('expired token → terminal error page, no account/membership', async () => {
    await seedInvite(rawDb, { id: 'inv-x', email: 'exp@acme.com', token: 'tok-x', expiresOffset: '-1 days' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-x', name: 'X', password: 'Sup3rPass!', confirmPassword: 'Sup3rPass!' }), env);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /expired/i);
    assert.equal((rawDb.prepare('SELECT COUNT(*) c FROM users').get() as { c: number }).c, 0);
  });

  it('platform invite with a non-allowed email is refused at accept time (defense-in-depth)', async () => {
    // Seed a platform invite whose email is NOT on the allowed domains (simulating
    // a tampered/legacy row) — accept must refuse rather than grant platform access.
    await seedInvite(rawDb, { id: 'inv-bad', email: 'outsider@gmail.com', tenantId: '__platform__', context: 'platform', subRole: 'support', token: 'tok-bad' });
    const res = await handleAcceptInvite(postReq({ token: 'tok-bad', name: 'X', password: 'Sup3rPass!', confirmPassword: 'Sup3rPass!' }), env);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Invitation unavailable/);
    assert.equal((rawDb.prepare('SELECT COUNT(*) c FROM tenant_memberships').get() as { c: number }).c, 0);
  });
});
