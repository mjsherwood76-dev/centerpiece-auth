/**
 * Unit tests for the internal team-invite handler (Fix_Team_Invites S3).
 *
 * Exercises handleInternalInvites end-to-end against an in-memory better-sqlite3
 * DB (real migrations) + a mock Env, fully offline. Covers: internal-secret gate,
 * context/subRole validation (no owner), platform domain gate, existence branch
 * (exists:true → no invite row), new-person branch (exists:false → token + row),
 * duplicate-live-invite 409, list-by-tenant, and idempotent revoke.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { handleInternalInvites } from '../../src/handlers/internalInvites.js';
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

/** Async D1 shim over better-sqlite3 with result.meta.changes + exec(). */
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

const SECRET = 'test-internal-secret';
const TENANT = 'tenant:acme';
const INVITER = 'user-owner-1';

function makeEnv(rawDb: Database.Database): Env {
  return {
    AUTH_DB: d1(rawDb),
    INTERNAL_SECRET: SECRET,
    PLATFORM_OWNER_EMAIL_DOMAINS: 'centerpiecelab.com,centerpiecelab.dev',
  } as unknown as Env;
}

function seedUser(rawDb: Database.Database, email: string, id = 'user-existing-1'): void {
  rawDb.prepare(
    `INSERT OR IGNORE INTO users (id, email, email_verified, password_hash, name) VALUES (?, ?, 0, 'h', 'Existing')`
  ).run(id, email.toLowerCase());
}

function req(method: string, path: string, opts: { secret?: boolean; body?: unknown } = {}): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (opts.secret !== false) headers['X-CP-Internal-Secret'] = SECRET;
  return new Request(`https://auth.test${path}`, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

describe('handleInternalInvites — POST create', () => {
  let rawDb: Database.Database;
  let env: Env;

  before(() => { rawDb = buildSchemaDb(); });
  after(() => rawDb.close());
  beforeEach(() => { rawDb.exec('DELETE FROM tenant_invites; DELETE FROM users;'); env = makeEnv(rawDb); });

  it('403 without the internal secret', async () => {
    const res = await handleInternalInvites(
      req('POST', '/api/internal/invites', { secret: false, body: { email: 'a@x.com', tenantId: TENANT, context: 'seller', subRole: 'manager', invitedBy: INVITER } }),
      env,
    );
    assert.equal(res.status, 403);
  });

  it('400 on missing fields', async () => {
    const res = await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'a@x.com', tenantId: TENANT, context: 'seller' } }),
      env,
    );
    assert.equal(res.status, 400);
  });

  it('400 rejects owner subRole', async () => {
    const res = await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'a@x.com', tenantId: TENANT, context: 'seller', subRole: 'owner', invitedBy: INVITER } }),
      env,
    );
    assert.equal(res.status, 400);
  });

  it('400 rejects an invalid context', async () => {
    const res = await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'a@x.com', tenantId: TENANT, context: 'customer', subRole: 'manager', invitedBy: INVITER } }),
      env,
    );
    assert.equal(res.status, 400);
  });

  it('403 platform invite with a non-allowed email domain (before any send)', async () => {
    const res = await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'outsider@gmail.com', tenantId: '__platform__', context: 'platform', subRole: 'support', invitedBy: INVITER } }),
      env,
    );
    assert.equal(res.status, 403);
    const body = await res.json() as { error: { code: string } };
    assert.equal(body.error.code, 'platform_role.email_domain_restricted');
    // No invite row created.
    const count = rawDb.prepare('SELECT COUNT(*) c FROM tenant_invites').get() as { c: number };
    assert.equal(count.c, 0);
  });

  it('400 platform context on a non-__platform__ tenant', async () => {
    const res = await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'ok@centerpiecelab.com', tenantId: TENANT, context: 'platform', subRole: 'support', invitedBy: INVITER } }),
      env,
    );
    assert.equal(res.status, 400);
  });

  it('exists:true for an email with an existing account — NO invite row created', async () => {
    seedUser(rawDb, 'member@acme.com', 'user-acme-1');
    const res = await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'Member@Acme.com', tenantId: TENANT, context: 'seller', subRole: 'manager', invitedBy: INVITER } }),
      env,
    );
    assert.equal(res.status, 200);
    const body = await res.json() as { exists: boolean; userId: string };
    assert.equal(body.exists, true);
    assert.equal(body.userId, 'user-acme-1');
    const count = rawDb.prepare('SELECT COUNT(*) c FROM tenant_invites').get() as { c: number };
    assert.equal(count.c, 0, 'existing account is auto-granted by platform-api, not invited');
  });

  it('exists:false for a new email — token returned once + hashed row stored', async () => {
    const res = await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'newbie@acme.com', tenantId: TENANT, context: 'seller', subRole: 'designer', invitedBy: INVITER } }),
      env,
    );
    assert.equal(res.status, 201);
    const body = await res.json() as { exists: boolean; token: string; inviteId: string; expiresAt: string; expiresInDays: number };
    assert.equal(body.exists, false);
    assert.ok(body.token && body.token.length >= 40, 'plaintext token returned');
    assert.equal(body.expiresInDays, 7);

    const row = rawDb.prepare('SELECT email, token_hash, sub_role FROM tenant_invites WHERE id = ?').get(body.inviteId) as { email: string; token_hash: string; sub_role: string };
    assert.equal(row.email, 'newbie@acme.com', 'stored lowercased');
    assert.equal(row.sub_role, 'designer');
    assert.notEqual(row.token_hash, body.token, 'plaintext token is never stored — only its hash');
    assert.ok(/^[0-9a-f]{64}$/.test(row.token_hash), 'token_hash is SHA-256 hex');
  });

  it('409 on a duplicate live invite for the same tuple', async () => {
    const make = () => handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'dup@acme.com', tenantId: TENANT, context: 'seller', subRole: 'manager', invitedBy: INVITER } }),
      env,
    );
    assert.equal((await make()).status, 201);
    const res2 = await make();
    assert.equal(res2.status, 409);
    const body = await res2.json() as { error: { code: string } };
    assert.equal(body.error.code, 'invite.already_pending');
  });
});

describe('handleInternalInvites — list + revoke', () => {
  let rawDb: Database.Database;
  let env: Env;

  before(() => { rawDb = buildSchemaDb(); });
  after(() => rawDb.close());
  beforeEach(() => { rawDb.exec('DELETE FROM tenant_invites; DELETE FROM users;'); env = makeEnv(rawDb); });

  it('GET by-tenant lists pending invites', async () => {
    await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'l1@acme.com', tenantId: TENANT, context: 'seller', subRole: 'manager', invitedBy: INVITER } }),
      env,
    );
    const res = await handleInternalInvites(req('GET', `/api/internal/invites/by-tenant?tenantId=${encodeURIComponent(TENANT)}`), env);
    assert.equal(res.status, 200);
    const list = await res.json() as Array<{ email: string; subRole: string }>;
    assert.equal(list.length, 1);
    assert.equal(list[0].email, 'l1@acme.com');
    assert.equal(list[0].subRole, 'manager');
  });

  it('DELETE /:id revokes (idempotent)', async () => {
    const created = await (await handleInternalInvites(
      req('POST', '/api/internal/invites', { body: { email: 'rev@acme.com', tenantId: TENANT, context: 'seller', subRole: 'manager', invitedBy: INVITER } }),
      env,
    )).json() as { inviteId: string };

    const res1 = await handleInternalInvites(req('DELETE', `/api/internal/invites/${created.inviteId}`), env);
    assert.equal(res1.status, 200);
    assert.equal((await res1.json() as { deleted: boolean }).deleted, true);

    const res2 = await handleInternalInvites(req('DELETE', `/api/internal/invites/${created.inviteId}`), env);
    assert.equal(res2.status, 200);
    assert.equal((await res2.json() as { deleted: boolean }).deleted, false, 'idempotent');
  });

  it('GET by-tenant requires tenantId', async () => {
    const res = await handleInternalInvites(req('GET', '/api/internal/invites/by-tenant'), env);
    assert.equal(res.status, 400);
  });
});
