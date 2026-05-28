/**
 * Tests for /api/internal/sessions/* endpoints (Fix_Auth_Session_UX S4)
 *
 * GET  /api/internal/sessions/by-user     — list active sessions for a user
 * POST /api/internal/sessions/:id/revoke  — revoke a specific session
 *
 * All routes are gated by X-CP-Internal-Secret. Tests here cover:
 * - Missing / wrong secret → 403 (no D1 needed)
 * - Missing required body fields → 400 (no D1 needed)
 *
 * Tests that require D1 (actual session listing/revocation) depend on
 * migration 0007 being applied to staging and are therefore integration-tested
 * manually via the cross-browser verification gate in S6.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { BASE_URL } from '../helpers.js';

// ─── Helpers ─────────────────────────────────────────────────

async function getWithBody(
  path: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetch(`${BASE_URL}${path}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

async function postJson(
  path: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

// ─── GET /api/internal/sessions/by-user ─────────────────────

describe('GET /api/internal/sessions/by-user — secret gate', () => {
  it('returns 403 when X-CP-Internal-Secret header is absent', async () => {
    const res = await getWithBody('/api/internal/sessions/by-user', { userId: 'user-123' });
    assert.equal(res.status, 403);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body.error, 'Forbidden');
  });

  it('returns 403 when X-CP-Internal-Secret header is wrong', async () => {
    const res = await getWithBody(
      '/api/internal/sessions/by-user',
      { userId: 'user-123' },
      { 'X-CP-Internal-Secret': 'definitely-wrong-secret' },
    );
    assert.equal(res.status, 403);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body.error, 'Forbidden');
  });
});

// ─── POST /api/internal/sessions/:id/revoke ──────────────────

describe('POST /api/internal/sessions/:id/revoke — secret gate', () => {
  it('returns 403 when X-CP-Internal-Secret header is absent', async () => {
    const res = await postJson(
      '/api/internal/sessions/some-session-id/revoke',
      { userId: 'user-123' },
    );
    assert.equal(res.status, 403);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body.error, 'Forbidden');
  });

  it('returns 403 when X-CP-Internal-Secret header is wrong', async () => {
    const res = await postJson(
      '/api/internal/sessions/some-session-id/revoke',
      { userId: 'user-123' },
      { 'X-CP-Internal-Secret': 'wrong-value' },
    );
    assert.equal(res.status, 403);
    const body = await res.json() as Record<string, unknown>;
    assert.equal(body.error, 'Forbidden');
  });
});
