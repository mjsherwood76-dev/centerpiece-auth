/**
 * Security Headers
 *
 * Adds security headers to all responses from the auth Worker:
 * - X-Frame-Options: DENY (prevent clickjacking)
 * - X-Content-Type-Options: nosniff
 * - Referrer-Policy: strict-origin-when-cross-origin
 * - Content-Security-Policy (CSP)
 * - Permissions-Policy
 *
 * Also provides a proper CORS preflight handler with origin validation.
 */
import type { Env } from '../types.js';
import { CONTROLLED_SUFFIXES, CONTROLLED_HOSTS, isControlledHostname } from './platformDomains.js';

/** Dev-only allowed origins. */
const DEV_ORIGINS = ['http://localhost', 'http://127.0.0.1'];

/**
 * Add security headers to a response.
 * Creates a new Response with the security headers appended.
 * Optionally merges trace headers (x-trace-id, Server-Timing).
 */
export function addSecurityHeaders(
  response: Response,
  traceHeaders?: Record<string, string>,
  request?: Request,
  env?: Env
): Response {
  const headers = new Headers(response.headers);

  // ── CORS response headers for cross-origin requests ──
  if (request && env) {
    const origin = request.headers.get('Origin') || '';
    if (origin && isAllowedOrigin(origin, env)) {
      headers.set('Access-Control-Allow-Origin', origin);
      headers.set('Access-Control-Allow-Credentials', 'true');
      headers.set('Vary', 'Origin');
    }
  }

  // Prevent clickjacking
  if (!headers.has('X-Frame-Options')) {
    headers.set('X-Frame-Options', 'DENY');
  }

  // Prevent MIME type sniffing
  if (!headers.has('X-Content-Type-Options')) {
    headers.set('X-Content-Type-Options', 'nosniff');
  }

  // Control referrer information
  if (!headers.has('Referrer-Policy')) {
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  }

  // Content Security Policy for HTML pages
  const contentType = headers.get('Content-Type') || '';
  if (contentType.includes('text/html')) {
    if (!headers.has('Content-Security-Policy')) {
      headers.set(
        'Content-Security-Policy',
        [
          "default-src 'self'",
          // Allow inline styles for CSS variables and theme injection
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
          // Allow inline scripts for FOUC prevention and dark mode toggle.
          // static.cloudflareinsights.com hosts the Web Analytics beacon that
          // Cloudflare auto-injects when zone-level Web Analytics is enabled —
          // without this allowance the browser blocks the beacon and emits a
          // CSP-violation log every page load.
          "script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com",
          "font-src 'self' https://fonts.gstatic.com",
          // Allow images from any https source (tenant logos, avatars)
          "img-src 'self' https: data:",
          // Form actions to self + controlled platform domains.
          // CSP Level 3 checks redirect destinations after form POST,
          // so form-action must include origins the server redirects to
          // (e.g. admin panel callback after login).
          `form-action 'self' ${[
            ...CONTROLLED_SUFFIXES.map(s => `https://*${s}`),
            ...CONTROLLED_HOSTS.map(h => `https://${h}`),
          ].join(' ')}`,
          // Block embedding in frames
          "frame-ancestors 'none'",
          // Base URI restriction
          "base-uri 'self'",
          // Connect to auth domain APIs + CF Web Analytics beacon
          // (cloudflareinsights.com is the POST target for the auto-injected
          // beacon when zone Web Analytics is enabled).
          "connect-src 'self' https://cloudflareinsights.com",
        ].join('; ')
      );
    }
  }

  // Restrict browser features
  if (!headers.has('Permissions-Policy')) {
    headers.set(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=()'
    );
  }

  // Merge trace headers (x-trace-id, Server-Timing) if provided
  if (traceHeaders) {
    for (const [key, value] of Object.entries(traceHeaders)) {
      headers.set(key, value);
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Handle CORS preflight with origin validation.
 *
 * Rules:
 * - Only allow known tenant origins + controlled suffixes
 * - Never use `*` with credentials
 * - Set `Vary: Origin`
 */
export function handleCorsPreflightValidated(request: Request, env: Env): Response {
  const origin = request.headers.get('Origin') || '';
  const isAllowed = isAllowedOrigin(origin, env);

  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };

  if (isAllowed && origin) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }

  return new Response(null, { status: 204, headers });
}

/**
 * Check if an origin is allowed for CORS.
 */
function isAllowedOrigin(origin: string, env: Env): boolean {
  if (!origin) return false;

  try {
    const url = new URL(origin);
    const hostname = url.hostname;

    // Check controlled hosts + suffixes (exact platform hosts on public
    // deploy suffixes; arbitrary workers.dev/pages.dev origins are NOT
    // allowed — credentialed-CORS fix, 2026-06-10 review H1)
    if (isControlledHostname(hostname)) return true;

    // Check dev origins
    const isDev = env.ENVIRONMENT !== 'production';
    if (isDev) {
      for (const devOrigin of DEV_ORIGINS) {
        if (origin.startsWith(devOrigin)) return true;
      }
    }

    // The auth domain itself
    if (origin === env.AUTH_DOMAIN) return true;

    return false;
  } catch {
    return false;
  }
}
