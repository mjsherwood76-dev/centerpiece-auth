/**
 * Policy-coverage tests for centerpiece-auth's rate limiting (Phase 3.12, S2).
 *
 * The shared RateLimiter logic itself is unit-tested in
 * centerpiece-site-compositor. These tests assert the AUTH-side contract that
 * matters to this repo: the credential-bearing routes the retired
 * src/security/rateLimit.ts limiter protected (POST /api/{login,register,
 * forgot-password,reset-password,switch-tenant} + /api/auth/step-up) are still
 * matched by AUTH_POLICIES, the OAuth POST surfaces are now covered too, and
 * the table is ordered most-specific-first so no rule is shadowed.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  AUTH_POLICIES,
  matchPolicy,
  assertPolicyOrdering,
} from '@centerpiece/site-compositor/security';

function reqFor(path: string): Request {
  return new Request(`https://auth.centerpiecelab.com${path}`);
}

describe('AUTH_POLICIES coverage', () => {
  // Routes the retired limiter guarded, plus the net-new OAuth surfaces.
  const COVERED = [
    '/api/login',
    '/api/register',
    '/api/forgot-password',
    '/api/reset-password',
    '/api/switch-tenant',
    '/api/auth/step-up',
    '/oauth/authorize',
    '/oauth/token',
  ];

  for (const route of COVERED) {
    it(`matches a policy for ${route}`, () => {
      const policy = matchPolicy(reqFor(route), AUTH_POLICIES);
      assert.notEqual(policy, null, `expected a policy for ${route}`);
      assert.equal(policy!.scope, 'ip', `${route} must be IP-scoped (pre-auth)`);
      assert.equal(policy!.onLimit, 'block', `${route} must block on limit`);
    });
  }

  it('does NOT limit GET page loads (/login, /register, /reset-password)', () => {
    // These are branded HTML page renders, not the credential POST surface.
    for (const page of ['/login', '/register', '/reset-password']) {
      assert.equal(
        matchPolicy(reqFor(page), AUTH_POLICIES),
        null,
        `${page} page load must not be rate-limited`,
      );
    }
  });

  it('does NOT limit health / JWKS / well-known endpoints', () => {
    for (const open of ['/health', '/.well-known/jwks.json', '/.well-known/oauth-authorization-server']) {
      assert.equal(matchPolicy(reqFor(open), AUTH_POLICIES), null);
    }
  });

  it('is ordered most-specific-first (no shadowed rules)', () => {
    assert.equal(assertPolicyOrdering(AUTH_POLICIES), null);
  });
});
