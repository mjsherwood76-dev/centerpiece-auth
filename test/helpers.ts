/**
 * Test Helpers — Staging Integration Tests
 *
 * Utilities for making HTTP requests against the staging auth Worker.
 * All tests run against:
 *   https://centerpiece-auth-staging.mjsherwood76.workers.dev
 *
 * These are real integration tests — real D1, real KV, real crypto.
 */

/** Staging base URL for the auth Worker. */
export const BASE_URL = 'https://centerpiece-auth-staging.mjsherwood76.workers.dev';

/** A controlled-suffix redirect URL that passes validation. */
export const VALID_REDIRECT = 'https://test-store.centerpiece.shop/shop';

/** Generate a unique email for test isolation. */
export function uniqueEmail(): string {
  const ts = Date.now();
  const rand = Math.random().toString(36).substring(2, 8);
  return `test-${ts}-${rand}@centerpiece-test.shop`;
}

/**
 * POST form-urlencoded data to a staging endpoint.
 * Returns the raw Response (does NOT follow redirects).
 */
export async function postForm(
  path: string,
  data: Record<string, string>,
): Promise<Response> {
  const body = new URLSearchParams(data);
  return fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    redirect: 'manual', // Don't follow redirects — we inspect Location header
  });
}

/**
 * POST JSON data to a staging endpoint.
 */
export async function postJson(
  path: string,
  data: Record<string, unknown>,
): Promise<Response> {
  return fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
    redirect: 'manual',
  });
}

/**
 * GET request to a staging endpoint.
 */
export async function get(
  path: string,
  headers?: Record<string, string>,
): Promise<Response> {
  return fetch(`${BASE_URL}${path}`, {
    method: 'GET',
    headers: headers || {},
    redirect: 'manual',
  });
}

/**
 * Extract a query parameter from a redirect Location header.
 */
export function getLocationParam(response: Response, param: string): string | null {
  const location = response.headers.get('Location');
  if (!location) return null;
  try {
    const url = new URL(location);
    return url.searchParams.get(param);
  } catch {
    return null;
  }
}

/**
 * Register a user and return the auth code from the redirect.
 * Convenience wrapper for tests that need an authenticated user.
 */
export async function registerUser(
  email: string,
  password: string,
  name?: string,
): Promise<{ response: Response; code: string | null; refreshCookie: string | null }> {
  const response = await postForm('/api/register', {
    email,
    password,
    confirmPassword: password,
    name: name || 'Test User',
    tenant: 'test-tenant',
    redirect: VALID_REDIRECT,
  });
  const code = getLocationParam(response, 'code');
  const refreshCookie = response.headers.get('Set-Cookie');
  return { response, code, refreshCookie };
}
