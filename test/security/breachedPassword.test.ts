/**
 * Unit tests for src/security/breachedPassword.ts
 *
 * These tests run in Node.js (node:test + tsx). They mock globalThis.fetch so
 * no network requests leave the test process.
 *
 * k-anonymity verified: we capture the URL called by fetch and assert that it
 * contains only the 5-character prefix, never the full hash or plaintext password.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { isPasswordBreached } from '../../src/security/breachedPassword.js';

// ─── Minimal Env stub ──────────────────────────────────────────────────────────

type TestEnv = { ENVIRONMENT: string; PASSWORD_BREACH_CHECK_ENABLED?: string };

const testEnv: TestEnv = { ENVIRONMENT: 'test' };

// ─── SHA-1 helper (mirrors the production code; used to build fixture data) ───

async function sha1Hex(password: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

// ─── Fetch mock infrastructure ─────────────────────────────────────────────────

type FetchImpl = typeof globalThis.fetch;
let originalFetch: FetchImpl;

before(() => {
  originalFetch = globalThis.fetch;
});

after(() => {
  globalThis.fetch = originalFetch;
});

function mockFetchWithBody(body: string, status = 200): string[] {
  const calledUrls: string[] = [];
  globalThis.fetch = async (input: RequestInfo | URL, _init?: RequestInit) => {
    calledUrls.push(typeof input === 'string' ? input : String(input));
    return new Response(body, { status });
  };
  return calledUrls;
}

function mockFetchNetworkError(): void {
  globalThis.fetch = async () => {
    throw new TypeError('Failed to fetch');
  };
}

function mockFetchTimeout(): void {
  // Simulate a slow response that gets aborted by the signal.
  globalThis.fetch = (_input: RequestInfo | URL, init?: RequestInit) => {
    return new Promise<Response>((_, reject) => {
      const signal = init?.signal as AbortSignal | undefined;
      if (signal) {
        signal.addEventListener('abort', () =>
          reject(Object.assign(new Error('The operation was aborted.'), { name: 'AbortError' })),
        );
      }
      // Never resolves — simulates a hung server; the timeout in the module aborts it.
    });
  };
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

describe('isPasswordBreached', () => {
  it('returns true when the password suffix is in the HIBP response', async () => {
    const password = 'password'; // Known to be heavily breached
    const fullHash = await sha1Hex(password);
    const suffix = fullHash.slice(5);

    // Build a response that includes this suffix with a high count.
    const hibpBody = [
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1',
      `${suffix}:3730471`,
      'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2',
    ].join('\r\n');

    const calledUrls = mockFetchWithBody(hibpBody, 200);
    const breached = await isPasswordBreached(password, testEnv);

    assert.equal(breached, true, 'known-breached password should return true');
    assert.equal(calledUrls.length, 1, 'should make exactly one HIBP request');
  });

  it('returns false when the suffix is absent from the HIBP response', async () => {
    const password = 'xK9#mQ2vLp!rN4sZ'; // Unique — unlikely in corpus
    const fullHash = await sha1Hex(password);
    const suffix = fullHash.slice(5);

    // Response that explicitly does NOT contain our suffix.
    const otherSuffix = suffix === 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      ? 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
      : 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const hibpBody = `${otherSuffix}:1\r\nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:5\r\n`;

    mockFetchWithBody(hibpBody, 200);
    const breached = await isPasswordBreached(password, testEnv);

    assert.equal(breached, false, 'absent suffix should return false');
  });

  it('verifies k-anonymity: only the 5-char prefix is sent to HIBP', async () => {
    const password = 'testpassword123';
    const fullHash = await sha1Hex(password);
    const prefix = fullHash.slice(0, 5);

    const calledUrls = mockFetchWithBody('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1', 200);
    await isPasswordBreached(password, testEnv);

    assert.equal(calledUrls.length, 1, 'should call HIBP once');
    const calledUrl = calledUrls[0];
    // URL must end with the 5-char prefix only.
    assert.ok(
      calledUrl.endsWith(`/${prefix}`),
      `URL should end with /PREFIX (only 5 chars). Got: ${calledUrl}`,
    );
    // Full hash must NOT appear in the URL.
    assert.ok(
      !calledUrl.includes(fullHash),
      'Full hash must not be sent to HIBP',
    );
    // Plaintext password must never appear in the URL.
    assert.ok(
      !calledUrl.includes(encodeURIComponent(password)) && !calledUrl.includes(password),
      'Plaintext password must not be sent to HIBP',
    );
  });

  it('fails open (returns false) when HIBP returns a non-200 status', async () => {
    mockFetchWithBody('Internal Server Error', 500);
    const breached = await isPasswordBreached('anypassword', testEnv);
    assert.equal(breached, false, 'should fail open on HIBP 5xx');
  });

  it('fails open (returns false) on a network error', async () => {
    mockFetchNetworkError();
    const breached = await isPasswordBreached('anypassword', testEnv);
    assert.equal(breached, false, 'should fail open on network error');
  });

  it('fails open (returns false) on a timeout (AbortError)', async () => {
    mockFetchTimeout();
    const breached = await isPasswordBreached('anypassword', testEnv);
    assert.equal(breached, false, 'should fail open on timeout');
  });

  it('skips the check entirely when PASSWORD_BREACH_CHECK_ENABLED is "false"', async () => {
    const calledUrls: string[] = [];
    globalThis.fetch = async (input: RequestInfo | URL) => {
      calledUrls.push(String(input));
      return new Response('', { status: 200 });
    };

    const env: TestEnv = { ENVIRONMENT: 'test', PASSWORD_BREACH_CHECK_ENABLED: 'false' };
    const breached = await isPasswordBreached('password', env);

    assert.equal(breached, false, 'should return false when flag is disabled');
    assert.equal(calledUrls.length, 0, 'should not call HIBP when flag is disabled');
  });

  it('skips the check entirely when PASSWORD_BREACH_CHECK_ENABLED is "0"', async () => {
    const calledUrls: string[] = [];
    globalThis.fetch = async (input: RequestInfo | URL) => {
      calledUrls.push(String(input));
      return new Response('', { status: 200 });
    };

    const env: TestEnv = { ENVIRONMENT: 'test', PASSWORD_BREACH_CHECK_ENABLED: '0' };
    const breached = await isPasswordBreached('password', env);

    assert.equal(breached, false, 'should return false when flag is 0');
    assert.equal(calledUrls.length, 0, 'should not call HIBP when flag is 0');
  });

  it('runs the check when PASSWORD_BREACH_CHECK_ENABLED is absent (default enabled)', async () => {
    const calledUrls = mockFetchWithBody('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1', 200);
    const env: TestEnv = { ENVIRONMENT: 'test' }; // No flag set
    await isPasswordBreached('anypassword', env);
    assert.equal(calledUrls.length, 1, 'should call HIBP when flag is absent');
  });

  it('returns false (not breached) for a suffix with count 0', async () => {
    const password = 'zerocountpassword!';
    const fullHash = await sha1Hex(password);
    const suffix = fullHash.slice(5);

    // HIBP can return padded entries with count 0.
    const hibpBody = `${suffix}:0\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\r\n`;
    mockFetchWithBody(hibpBody, 200);
    const breached = await isPasswordBreached(password, testEnv);
    assert.equal(breached, false, 'count:0 should not be treated as breached');
  });
});
