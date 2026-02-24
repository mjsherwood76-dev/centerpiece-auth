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

/** Controlled domain suffixes for CORS origin validation. */
const CONTROLLED_SUFFIXES = [
  '.centerpiece.shop',
  '.centerpiece.app',
  '.centerpiece.io',
  '.workers.dev',
  '.pages.dev',
  '.centerpiecelab.com',
];

/** Dev-only allowed origins. */
const DEV_ORIGINS = ['http://localhost', 'http://127.0.0.1'];

/**
 * Add security headers to a response.
 * Creates a new Response with the security headers appended.
 */
export function addSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);

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
          // Allow inline scripts for FOUC prevention and dark mode toggle
          "script-src 'self' 'unsafe-inline'",
          "font-src 'self' https://fonts.gstatic.com",
          // Allow images from any https source (tenant logos, avatars)
          "img-src 'self' https: data:",
          // Form actions only to self (auth domain)
          "form-action 'self'",
          // Block embedding in frames
          "frame-ancestors 'none'",
          // Base URI restriction
          "base-uri 'self'",
          // Connect to auth domain APIs
          "connect-src 'self'",
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

    // Check controlled suffixes
    for (const suffix of CONTROLLED_SUFFIXES) {
      if (hostname.endsWith(suffix)) return true;
    }

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
