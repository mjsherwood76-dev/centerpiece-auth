/**
 * Step-Up Auth Handler
 *
 * POST /api/auth/step-up — Re-confirm password to mint a short-lived step-up token
 *
 * Auth: Bearer JWT required (current admin access token; `aud: 'admin'`).
 * Body: { password: string, step_up_for: string }
 *
 * Flow:
 * 1. Verify caller's JWT (signature + expiry + admin audience)
 * 2. Reject impersonation tokens (step-up cannot bypass the impersonation guard)
 * 3. Parse + validate body (`password`, `step_up_for`)
 * 4. Look up user by JWT sub; verify password (constant-time)
 * 5. Mint a 5-minute step-up JWT bound to the `step_up_for` descriptor
 *
 * Security:
 * - Generic error message for wrong password ("Invalid credentials")
 * - Step-up TTL is intentionally short (5 minutes) — caller embeds the returned
 *   token in the immediately-following sensitive request via `X-CP-Step-Up`
 * - The middleware on the consuming endpoint verifies BOTH freshness AND
 *   that `step_up_for` matches the resource being mutated
 * - Constant-time dummy hash on user-missing path to prevent enumeration
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { verifyJwt, signJwt, buildStepUpJwtPayload } from '../crypto/jwt.js';
import { verifyPassword } from '../crypto/passwords.js';
import { jsonError } from '../util/httpJson.js';

/** Step-up tokens are short-lived; long enough for the user to confirm and submit. */
const STEP_UP_TTL_SECONDS = 300; // 5 minutes

/** Max length on the step_up_for descriptor (bounded to avoid abuse). */
const MAX_STEP_UP_FOR_LENGTH = 256;

export async function handleStepUp(request: Request, env: Env): Promise<Response> {
  // ── Extract and verify caller's JWT ──
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonError('Unauthorized', 401);
  }

  const token = authHeader.slice(7);
  const payload = await verifyJwt(token, env.JWT_PUBLIC_KEY);
  if (!payload || payload.aud !== 'admin') {
    return jsonError('Unauthorized', 401);
  }

  // Impersonation sessions cannot step up — the impersonated user never
  // entered their password into this session.
  if (payload.sessionType === 'impersonation') {
    return jsonError('Step-up not available during impersonation', 403);
  }

  // ── Parse body ──
  let body: { password?: unknown; step_up_for?: unknown };
  try {
    body = await request.json() as { password?: unknown; step_up_for?: unknown };
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  const password = typeof body.password === 'string' ? body.password : '';
  const stepUpFor = typeof body.step_up_for === 'string' ? body.step_up_for.trim() : '';

  if (!password) {
    return jsonError('password is required', 400);
  }
  if (!stepUpFor) {
    return jsonError('step_up_for is required', 400);
  }
  if (stepUpFor.length > MAX_STEP_UP_FOR_LENGTH) {
    return jsonError('step_up_for too long', 400);
  }

  // ── Look up user, verify password ──
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const user = await db.getUserById(payload.sub);
  if (!user || !user.password_hash) {
    // OAuth-only users (or missing rows) cannot step up with a password.
    // Keep timing similar to the verify path via a dummy hash.
    await dummyHashDelay();
    return jsonError('Invalid credentials', 401);
  }

  const passwordValid = await verifyPassword(password, user.password_hash);
  if (!passwordValid) {
    return jsonError('Invalid credentials', 401);
  }

  // ── Issue step-up token ──
  const stepUpToken = await signJwt(
    buildStepUpJwtPayload({
      userId: user.id,
      email: user.email,
      name: user.name || '',
      iss: env.AUTH_DOMAIN,
      contexts: payload.contexts ?? {},
      primaryTenantId: payload.primaryTenantId ?? null,
      stepUpFor,
    }),
    env.JWT_PRIVATE_KEY,
    STEP_UP_TTL_SECONDS,
  );

  return new Response(
    JSON.stringify({
      step_up_token: stepUpToken,
      token_type: 'Bearer',
      expires_in: STEP_UP_TTL_SECONDS,
      step_up_for: stepUpFor,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    },
  );
}

/**
 * Perform a dummy PBKDF2 hash to make timing consistent whether the user
 * exists / has a password or not. Mirrors `handleLogin`.
 */
async function dummyHashDelay(): Promise<void> {
  const dummyKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('dummy-password'),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(32),
      iterations: 100_000,
      hash: 'SHA-256',
    },
    dummyKey,
    256,
  );
}
