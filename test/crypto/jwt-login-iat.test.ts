/**
 * Unit tests for login_iat JWT claim support.
 *
 * Tests that:
 * - buildAdminJwtPayload includes login_iat when provided
 * - buildAdminJwtPayload omits login_iat when not provided
 * - buildCustomerJwtPayload never includes login_iat
 * - buildImpersonationJwtPayload never includes login_iat
 *
 * Pure unit tests — no network, no D1, no Worker required.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAdminJwtPayload,
  buildCustomerJwtPayload,
  buildImpersonationJwtPayload,
} from '../../src/crypto/jwt.js';

const IDENTITY = {
  userId: 'user-abc',
  email: 'admin@centerpiecelab.com',
  name: 'Test Admin',
  iss: 'https://auth.centerpiecelab.com',
};

describe('buildAdminJwtPayload login_iat', () => {
  it('includes login_iat when provided', () => {
    const loginIat = 1700000000;
    const payload = buildAdminJwtPayload({
      ...IDENTITY,
      contexts: { seller: ['owner'] },
      primaryTenantId: 'tenant-1',
      loginIat,
    });
    assert.equal(payload.login_iat, loginIat, 'login_iat should be set');
  });

  it('omits login_iat when not provided', () => {
    const payload = buildAdminJwtPayload({
      ...IDENTITY,
      contexts: { seller: ['owner'] },
      primaryTenantId: 'tenant-1',
    });
    assert.equal(payload.login_iat, undefined, 'login_iat should be absent when not provided');
  });

  it('jti defaults to a random UUID when not provided', () => {
    const payload = buildAdminJwtPayload({
      ...IDENTITY,
      contexts: {},
      primaryTenantId: null,
    });
    assert.ok(typeof payload.jti === 'string' && payload.jti.length > 0, 'jti should be set');
  });

  it('honors a provided jti', () => {
    const jti = 'refresh-token-id-xyz';
    const payload = buildAdminJwtPayload({
      ...IDENTITY,
      contexts: {},
      primaryTenantId: null,
      jti,
    });
    assert.equal(payload.jti, jti);
  });

  it('aud is admin', () => {
    const payload = buildAdminJwtPayload({
      ...IDENTITY,
      contexts: {},
      primaryTenantId: null,
    });
    assert.equal(payload.aud, 'admin');
  });
});

describe('buildCustomerJwtPayload login_iat', () => {
  it('never includes login_iat', () => {
    const payload = buildCustomerJwtPayload(IDENTITY);
    assert.equal(payload.login_iat, undefined, 'storefront tokens must not have login_iat');
  });
});

describe('buildImpersonationJwtPayload login_iat', () => {
  it('never includes login_iat', () => {
    const payload = buildImpersonationJwtPayload({
      ...IDENTITY,
      tenantId: 'tenant-1',
      impersonatedBy: 'admin-user-id',
    });
    assert.equal(payload.login_iat, undefined, 'impersonation tokens must not have login_iat');
  });
});
