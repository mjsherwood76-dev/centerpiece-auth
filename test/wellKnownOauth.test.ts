/**
 * OAuth Authorization Server Metadata Tests (RFC 8414)
 *
 * Tests GET /.well-known/oauth-authorization-server returns a valid
 * RFC 8414 metadata document from the staging auth Worker.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { BASE_URL, get } from './helpers.js';

/** Expected issuer for the staging environment. */
const STAGING_ISSUER = 'https://auth.centerpiecelab.dev';

describe('GET /.well-known/oauth-authorization-server', () => {
  it('returns 200 with JSON content type', async () => {
    const res = await get('/.well-known/oauth-authorization-server');
    assert.equal(res.status, 200);

    const ct = res.headers.get('Content-Type') || '';
    assert.ok(ct.includes('application/json'), `expected application/json, got: ${ct}`);
  });

  it('issuer matches the staging environment URL', async () => {
    const res = await get('/.well-known/oauth-authorization-server');
    const body = (await res.json()) as Record<string, unknown>;

    assert.equal(
      body.issuer,
      STAGING_ISSUER,
      `issuer should be ${STAGING_ISSUER}, got: ${body.issuer}`,
    );
  });

  it('contains all required RFC 8414 fields', async () => {
    const res = await get('/.well-known/oauth-authorization-server');
    const body = (await res.json()) as Record<string, unknown>;

    // Required RFC 8414 fields
    assert.ok(typeof body.issuer === 'string' && body.issuer.length > 0, 'issuer must be present');
    assert.ok(typeof body.authorization_endpoint === 'string' && body.authorization_endpoint.length > 0, 'authorization_endpoint must be present');
    assert.ok(typeof body.token_endpoint === 'string' && body.token_endpoint.length > 0, 'token_endpoint must be present');
    assert.ok(Array.isArray(body.scopes_supported) && (body.scopes_supported as string[]).length > 0, 'scopes_supported must be a non-empty array');
    assert.ok(Array.isArray(body.response_types_supported) && (body.response_types_supported as string[]).includes('code'), 'response_types_supported must include "code"');
    assert.ok(Array.isArray(body.grant_types_supported), 'grant_types_supported must be an array');
    assert.ok((body.grant_types_supported as string[]).includes('authorization_code'), 'grant_types_supported must include authorization_code');
    assert.ok((body.grant_types_supported as string[]).includes('refresh_token'), 'grant_types_supported must include refresh_token');
    assert.ok(Array.isArray(body.token_endpoint_auth_methods_supported), 'token_endpoint_auth_methods_supported must be an array');
    assert.ok(Array.isArray(body.code_challenge_methods_supported) && (body.code_challenge_methods_supported as string[]).includes('S256'), 'code_challenge_methods_supported must include S256');
    assert.ok('service_documentation' in body, 'service_documentation field must be present');
  });

  it('registration_endpoint is null (no Dynamic Client Registration in v1)', async () => {
    const res = await get('/.well-known/oauth-authorization-server');
    const body = (await res.json()) as Record<string, unknown>;

    // Explicitly assert null — guards against accidental DCR enablement in future sessions.
    assert.equal(
      body.registration_endpoint,
      null,
      'registration_endpoint must be null (DCR not supported in v1)',
    );
  });
});
