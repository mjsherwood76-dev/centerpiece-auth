/**
 * Unit tests for the auth-consent same-origin allowance in validateRedirectUrl.
 *
 * The Phase 3.18 third-party consent flow bounces an unauthenticated seller to
 * `/login?redirect=<auth-origin /oauth/authorize url>` and returns there after
 * login. validateRedirectUrl must accept that EXACT same-origin URL when (and
 * only when) the caller opts in by passing its own origin — without weakening
 * the tenant-domain rules that protect every other redirect.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateRedirectUrl, AUTH_CONSENT_TENANT } from '../src/security/redirectValidator.js';

// Minimal KV stub — the consent allowance returns before any KV lookup; the
// unknown-domain path calls get() and should see "not found".
const kv = { get: async () => null } as unknown as KVNamespace;

const AUTH = 'https://auth.centerpiecelab.dev';
const AUTHORIZE = `${AUTH}/oauth/authorize?client_id=x&redirect_uri=https%3A%2F%2Fwww.centerpiecelab.dev%2Fcb&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=S256&state=s`;

describe('validateRedirectUrl — auth-consent allowance', () => {
  it('accepts the auth origin /oauth/authorize URL when authConsentOrigin is passed', async () => {
    const r = await validateRedirectUrl(AUTHORIZE, kv, 'staging', AUTH);
    assert.equal(r.valid, true);
    assert.equal(r.tenantId, AUTH_CONSENT_TENANT);
    assert.equal(r.origin, AUTH);
  });

  it('does NOT grant the consent sentinel without opt-in (auth origin is a controlled zone, but no session-only routing)', async () => {
    // *.centerpiecelab.dev is a controlled suffix, so the URL may still be a
    // "valid" redirect — but WITHOUT authConsentOrigin it must NOT receive the
    // AUTH_CONSENT_TENANT sentinel that triggers the session-only login branch.
    const r = await validateRedirectUrl(AUTHORIZE, kv, 'staging');
    assert.notEqual(r.tenantId, AUTH_CONSENT_TENANT);
  });

  it('does NOT grant the consent sentinel for a different path (allowance is path-exact)', async () => {
    const r = await validateRedirectUrl(`${AUTH}/admin/secrets`, kv, 'staging', AUTH);
    assert.notEqual(r.tenantId, AUTH_CONSENT_TENANT);
  });

  it('REJECTS a different origin even with the /oauth/authorize path (no open redirect, no sentinel)', async () => {
    const r = await validateRedirectUrl('https://attacker.example/oauth/authorize?x=1', kv, 'staging', AUTH);
    assert.equal(r.valid, false);
    assert.notEqual(r.tenantId, AUTH_CONSENT_TENANT);
  });

  it('REJECTS an attacker host that merely contains the auth origin as a prefix', async () => {
    // origin comparison is exact — not a substring/startsWith match
    const r = await validateRedirectUrl('https://auth.centerpiecelab.dev.attacker.example/oauth/authorize', kv, 'staging', AUTH);
    assert.equal(r.valid, false);
  });

  it('still rejects javascript: URIs even with authConsentOrigin set', async () => {
    const r = await validateRedirectUrl('javascript:alert(1)//auth.centerpiecelab.dev/oauth/authorize', kv, 'staging', AUTH);
    assert.equal(r.valid, false);
  });
});
