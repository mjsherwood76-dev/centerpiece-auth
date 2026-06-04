/**
 * Unit tests for isPlatformEmailAllowed (src/security/emailDomainCheck.ts)
 *
 * These are pure unit tests — no network, no D1, no Worker required.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isPlatformEmailAllowed, isEmailAllowedForTenant } from '../../src/security/emailDomainCheck.js';
import type { Env } from '../../src/types.js';

/** Build a minimal Env stub with just the domains var set. */
function makeEnv(domains: string): Env {
  return { PLATFORM_OWNER_EMAIL_DOMAINS: domains } as unknown as Env;
}

describe('isPlatformEmailAllowed', () => {
  // ── Single-domain (production) configuration ──────────────────────

  it('accepts an email matching the single allowed domain (.com)', () => {
    const env = makeEnv('centerpiecelab.com');
    assert.equal(isPlatformEmailAllowed('mike@centerpiecelab.com', env), true);
  });

  it('rejects an email whose domain does not match the single allowed domain', () => {
    const env = makeEnv('centerpiecelab.com');
    assert.equal(isPlatformEmailAllowed('mike@gmail.com', env), false);
  });

  it('rejects an email whose domain is a subdomain of the allowed domain', () => {
    // "sub.centerpiecelab.com" does NOT pass "@centerpiecelab.com" check
    const env = makeEnv('centerpiecelab.com');
    assert.equal(isPlatformEmailAllowed('mike@sub.centerpiecelab.com', env), false);
  });

  // ── Multi-domain (staging) configuration ─────────────────────────

  it('accepts an email matching the .com domain in a multi-domain list', () => {
    const env = makeEnv('centerpiecelab.com,centerpiecelab.dev');
    assert.equal(isPlatformEmailAllowed('mike@centerpiecelab.com', env), true);
  });

  it('accepts an email matching the .dev domain in a multi-domain list', () => {
    const env = makeEnv('centerpiecelab.com,centerpiecelab.dev');
    assert.equal(isPlatformEmailAllowed('test-user@centerpiecelab.dev', env), true);
  });

  it('rejects an email not matching any domain in a multi-domain list', () => {
    const env = makeEnv('centerpiecelab.com,centerpiecelab.dev');
    assert.equal(isPlatformEmailAllowed('attacker@evil.com', env), false);
  });

  // ── Edge cases ────────────────────────────────────────────────────

  it('rejects all emails when env var is an empty string (fail-closed)', () => {
    const env = makeEnv('');
    assert.equal(isPlatformEmailAllowed('mike@centerpiecelab.com', env), false);
  });

  it('trims whitespace around domain entries', () => {
    const env = makeEnv(' centerpiecelab.com , centerpiecelab.dev ');
    assert.equal(isPlatformEmailAllowed('mike@centerpiecelab.com', env), true);
    assert.equal(isPlatformEmailAllowed('test@centerpiecelab.dev', env), true);
  });

  it('rejects an email with a domain that only prefix-matches (no @ prefix check bypass)', () => {
    // "notcenterpiecelab.com" should not match "centerpiecelab.com"
    const env = makeEnv('centerpiecelab.com');
    assert.equal(isPlatformEmailAllowed('mike@notcenterpiecelab.com', env), false);
  });
});

describe('isEmailAllowedForTenant (Phase 3.25 per-tenant allowlist)', () => {
  const DOMAINS = ['valhallan.com', 'xpleague.com'];

  it('accepts an email matching the first allowed domain', () => {
    assert.equal(isEmailAllowedForTenant('someone@valhallan.com', DOMAINS), true);
  });

  it('accepts an email matching the second allowed domain', () => {
    assert.equal(isEmailAllowedForTenant('someone@xpleague.com', DOMAINS), true);
  });

  it('rejects an email whose domain is not on the allowlist', () => {
    assert.equal(isEmailAllowedForTenant('someone@gmail.com', DOMAINS), false);
  });

  it('fails closed on an empty allowlist', () => {
    assert.equal(isEmailAllowedForTenant('someone@valhallan.com', []), false);
  });

  it('rejects a subdomain of an allowed domain (exact @domain suffix only)', () => {
    assert.equal(isEmailAllowedForTenant('someone@sub.valhallan.com', DOMAINS), false);
  });

  it('rejects a prefix-collision domain', () => {
    assert.equal(isEmailAllowedForTenant('someone@notvalhallan.com', DOMAINS), false);
  });

  it('is case-insensitive on both email and allowlist', () => {
    assert.equal(isEmailAllowedForTenant('Someone@VALHALLAN.com', ['Valhallan.com']), true);
  });

  it('ignores blank/whitespace allowlist entries', () => {
    assert.equal(isEmailAllowedForTenant('someone@valhallan.com', ['', '  ', 'valhallan.com']), true);
  });
});
