/**
 * Unit tests for db.invites.ts helpers (Fix_Team_Invites S2).
 *
 * Runs the REAL exported helper functions against an in-memory better-sqlite3
 * database initialized with all migrations, wrapped in a thin async shim that
 * presents the D1 API (.prepare().bind().first()/.all()/.run() with
 * result.meta.changes). This validates the helper LOGIC (auto-purge on
 * re-invite, pending-vs-expired filtering, single-use accept guard), not just
 * raw SQL execution (the schema test already covers SQL paths).
 *
 * Offline + deterministic — no network, runs in <1s.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  createInvite,
  hasPendingInvite,
  getInvitesByTenant,
  getInviteByTokenHash,
  markInviteAccepted,
  deleteInvite,
  deleteExpiredInvites,
} from '../src/db.invites.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(__dirname, '../migrations');

function buildSchemaDb(): Database.Database {
  const db = new Database(':memory:');
  const files = readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
  for (const f of files) {
    try { db.exec(readFileSync(join(migrationsDir, f), 'utf8')); } catch { /* see schema test note */ }
  }
  return db;
}

/** Minimal async D1 shim over better-sqlite3 with result.meta.changes. */
function d1(db: Database.Database): D1Database {
  return {
    prepare(sql: string) {
      const stmt = db.prepare(sql);
      const make = (args: unknown[]) => ({
        async first<T = unknown>(): Promise<T | null> {
          return (stmt.get(...(args as [])) as T) ?? null;
        },
        async all<T = unknown>(): Promise<{ results: T[] }> {
          return { results: stmt.all(...(args as [])) as T[] };
        },
        async run() {
          const r = stmt.run(...(args as []));
          return { success: true, meta: { changes: r.changes } };
        },
        bind(...a: unknown[]) { return make(a); },
      });
      return make([]) as unknown as D1PreparedStatement;
    },
  } as unknown as D1Database;
}

const TENANT = 'tenant:test-invites';
const INVITER = 'user-inviter-1';

describe('db.invites — createInvite / pending / accept / revoke', () => {
  let raw: Database.Database;
  let db: D1Database;

  before(() => { raw = buildSchemaDb(); });
  after(() => raw.close());
  beforeEach(() => { raw.exec('DELETE FROM tenant_invites;'); db = d1(raw); });

  it('createInvite inserts a pending row that hasPendingInvite + getInvitesByTenant see', async () => {
    await createInvite(db, {
      id: 'inv-a', email: 'New@Example.com', tenantId: TENANT,
      context: 'seller', subRole: 'manager', tokenHash: 'h1', invitedBy: INVITER,
    });
    assert.equal(await hasPendingInvite(db, 'new@example.com', TENANT, 'seller', 'manager'), true);
    const list = await getInvitesByTenant(db, TENANT);
    assert.equal(list.length, 1);
    assert.equal(list[0].email, 'new@example.com', 'email is lowercased at rest');
    assert.equal(list[0].accepted_at, null);
  });

  it('getInviteByTokenHash returns the row', async () => {
    await createInvite(db, {
      id: 'inv-b', email: 'b@example.com', tenantId: TENANT,
      context: 'platform', subRole: 'support', tokenHash: 'h-b', invitedBy: INVITER,
    });
    const row = await getInviteByTokenHash(db, 'h-b');
    assert.ok(row);
    assert.equal(row!.sub_role, 'support');
    assert.equal(await getInviteByTokenHash(db, 'nope'), null);
  });

  it('createInvite auto-purges an EXPIRED unaccepted row for the same tuple (re-invite)', async () => {
    // Seed an already-expired row directly.
    raw.prepare(
      `INSERT INTO tenant_invites (id,email,tenant_id,context,sub_role,token_hash,invited_by,created_at,expires_at,accepted_at)
       VALUES (?,?,?,?,?,?,?,datetime('now','-10 days'),datetime('now','-3 days'),NULL)`
    ).run('inv-old', 'c@example.com', TENANT, 'seller', 'manager', 'h-old', INVITER);

    // Re-invite same tuple must succeed (UNIQUE would otherwise block it).
    await createInvite(db, {
      id: 'inv-new', email: 'c@example.com', tenantId: TENANT,
      context: 'seller', subRole: 'manager', tokenHash: 'h-new', invitedBy: INVITER,
    });
    const list = await getInvitesByTenant(db, TENANT);
    assert.equal(list.length, 1, 'only the fresh invite remains');
    assert.equal(list[0].id, 'inv-new');
  });

  it('createInvite does NOT purge a still-pending row → UNIQUE violation (live dup)', async () => {
    await createInvite(db, {
      id: 'inv-1', email: 'd@example.com', tenantId: TENANT,
      context: 'seller', subRole: 'manager', tokenHash: 'h-1', invitedBy: INVITER,
    });
    await assert.rejects(
      createInvite(db, {
        id: 'inv-2', email: 'd@example.com', tenantId: TENANT,
        context: 'seller', subRole: 'manager', tokenHash: 'h-2', invitedBy: INVITER,
      }),
      /UNIQUE|constraint/i,
      'a live pending invite for the same tuple is not silently replaced',
    );
  });

  it('a different sub_role for the same email/tenant coexists', async () => {
    await createInvite(db, {
      id: 'inv-m', email: 'e@example.com', tenantId: TENANT,
      context: 'seller', subRole: 'manager', tokenHash: 'h-m', invitedBy: INVITER,
    });
    await createInvite(db, {
      id: 'inv-d', email: 'e@example.com', tenantId: TENANT,
      context: 'seller', subRole: 'designer', tokenHash: 'h-d', invitedBy: INVITER,
    });
    assert.equal((await getInvitesByTenant(db, TENANT)).length, 2);
  });

  it('markInviteAccepted is single-use and excludes the row from pending listings', async () => {
    await createInvite(db, {
      id: 'inv-acc', email: 'f@example.com', tenantId: TENANT,
      context: 'seller', subRole: 'manager', tokenHash: 'h-acc', invitedBy: INVITER,
    });
    assert.equal(await markInviteAccepted(db, 'inv-acc'), true, 'first accept succeeds');
    assert.equal(await markInviteAccepted(db, 'inv-acc'), false, 'second accept is rejected (single-use)');
    assert.equal((await getInvitesByTenant(db, TENANT)).length, 0, 'accepted invite is no longer pending');
    assert.equal(await hasPendingInvite(db, 'f@example.com', TENANT, 'seller', 'manager'), false);
  });

  it('markInviteAccepted refuses an expired row', async () => {
    raw.prepare(
      `INSERT INTO tenant_invites (id,email,tenant_id,context,sub_role,token_hash,invited_by,created_at,expires_at,accepted_at)
       VALUES (?,?,?,?,?,?,?,datetime('now','-10 days'),datetime('now','-1 days'),NULL)`
    ).run('inv-exp', 'g@example.com', TENANT, 'seller', 'manager', 'h-exp', INVITER);
    assert.equal(await markInviteAccepted(db, 'inv-exp'), false, 'expired invite cannot be accepted');
  });

  it('expired/unaccepted rows are excluded from hasPendingInvite + getInvitesByTenant', async () => {
    raw.prepare(
      `INSERT INTO tenant_invites (id,email,tenant_id,context,sub_role,token_hash,invited_by,created_at,expires_at,accepted_at)
       VALUES (?,?,?,?,?,?,?,datetime('now','-10 days'),datetime('now','-1 days'),NULL)`
    ).run('inv-exp2', 'h@example.com', TENANT, 'seller', 'manager', 'h-exp2', INVITER);
    assert.equal(await hasPendingInvite(db, 'h@example.com', TENANT, 'seller', 'manager'), false);
    assert.equal((await getInvitesByTenant(db, TENANT)).length, 0);
  });

  it('deleteInvite removes a pending invite (idempotent)', async () => {
    await createInvite(db, {
      id: 'inv-rev', email: 'i@example.com', tenantId: TENANT,
      context: 'seller', subRole: 'manager', tokenHash: 'h-rev', invitedBy: INVITER,
    });
    assert.equal(await deleteInvite(db, 'inv-rev'), true);
    assert.equal(await deleteInvite(db, 'inv-rev'), false, 'idempotent — second delete is a no-op');
  });

  it('deleteExpiredInvites removes only expired unaccepted rows', async () => {
    await createInvite(db, {
      id: 'inv-live', email: 'j@example.com', tenantId: TENANT,
      context: 'seller', subRole: 'manager', tokenHash: 'h-live', invitedBy: INVITER,
    });
    raw.prepare(
      `INSERT INTO tenant_invites (id,email,tenant_id,context,sub_role,token_hash,invited_by,created_at,expires_at,accepted_at)
       VALUES (?,?,?,?,?,?,?,datetime('now','-10 days'),datetime('now','-1 days'),NULL)`
    ).run('inv-dead', 'k@example.com', TENANT, 'seller', 'manager', 'h-dead', INVITER);
    const removed = await deleteExpiredInvites(db);
    assert.equal(removed, 1, 'only the expired row is removed');
    assert.equal((await getInvitesByTenant(db, TENANT)).length, 1);
  });
});
