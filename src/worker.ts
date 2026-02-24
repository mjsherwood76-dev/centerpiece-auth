/**
 * Centerpiece Auth Worker — Entry Point
 *
 * Handles all identity concerns: registration, login, OAuth,
 * JWT issuance, refresh token management.
 *
 * Deployed on auth.centerpiecelab.com (or staging equivalent).
 */
import type { Env } from './types.js';
import { handleHealth } from './handlers/health.js';
import { handleJWKS } from './handlers/jwks.js';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    // --- CORS preflight (browser-facing endpoints only) ---
    if (method === 'OPTIONS') {
      return handleCorsPreflightPlaceholder(request);
    }

    try {
      // --- Health ---
      if (method === 'GET' && path === '/health') {
        return handleHealth(env);
      }

      // --- JWKS (public key for JWT verification) ---
      if (method === 'GET' && path === '/.well-known/jwks.json') {
        return handleJWKS(env);
      }

      // --- Pages (Session 2) ---
      // GET /login   → branded login page
      // GET /register → branded register page
      // GET /reset-password → branded reset form

      // --- API endpoints (Session 3) ---
      // POST /api/register
      // POST /api/login
      // POST /api/token
      // GET  /api/refresh
      // POST /api/forgot-password
      // POST /api/reset-password
      // POST /api/logout
      // POST /api/logout-all

      // --- OAuth routes (Session 4) ---
      // GET  /oauth/google
      // GET  /oauth/google/callback
      // GET  /oauth/facebook
      // GET  /oauth/facebook/callback
      // GET  /oauth/apple
      // POST /oauth/apple/callback
      // GET  /oauth/microsoft
      // GET  /oauth/microsoft/callback

      // --- 404 ---
      return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Internal server error';
      console.error('Auth Worker error:', message);
      return new Response(JSON.stringify({ error: 'Internal server error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
} satisfies ExportedHandler<Env>;

/**
 * Minimal CORS preflight handler.
 * Full CORS logic with origin validation will be added in Session 6 (hardening).
 */
function handleCorsPreflightPlaceholder(_request: Request): Response {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    },
  });
}
