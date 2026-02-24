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
import { handleLoginPage } from './pages/login.js';
import { handleRegisterPage } from './pages/register.js';
import { handleRegister } from './handlers/register.js';
import { handleLogin } from './handlers/login.js';
import { handleTokenExchange } from './handlers/token.js';
import { handleRefresh } from './handlers/refresh.js';
import { handleLogout, handleLogoutAll } from './handlers/logout.js';
import { handleGoogleOAuthInit, handleGoogleOAuthCallback } from './oauth/google.js';
import { handleFacebookOAuthInit, handleFacebookOAuthCallback } from './oauth/facebook.js';
import { handleAppleOAuthInit, handleAppleOAuthCallback } from './oauth/apple.js';
import { handleMicrosoftOAuthInit, handleMicrosoftOAuthCallback } from './oauth/microsoft.js';
import { handleForgotPassword } from './handlers/forgotPassword.js';
import { handleResetPassword } from './handlers/resetPassword.js';
import { handleResetPasswordPage } from './pages/resetPassword.js';
import { checkRateLimit } from './security/rateLimit.js';
import { addSecurityHeaders, handleCorsPreflightValidated } from './security/headers.js';
import { logAuthEvent } from './security/auditLog.js';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;
    const clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';

    // --- CORS preflight (browser-facing endpoints only) ---
    if (method === 'OPTIONS') {
      return handleCorsPreflightValidated(request, env);
    }

    try {
      // --- Rate limiting for sensitive endpoints ---
      const rateLimitedRoutes = ['/api/login', '/api/register', '/api/forgot-password', '/api/reset-password'];
      if (method === 'POST' && rateLimitedRoutes.includes(path)) {
        const rateLimitResult = await checkRateLimit(clientIp, path, env);
        if (!rateLimitResult.allowed) {
          await logAuthEvent(env, {
            event: 'rate_limit_exceeded',
            ip: clientIp,
            route: path,
            userAgent: request.headers.get('User-Agent'),
          });
          return addSecurityHeaders(new Response(JSON.stringify({ error: 'Too many requests. Please try again later.' }), {
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'Retry-After': String(rateLimitResult.retryAfterSeconds),
            },
          }));
        }
      }

      let response: Response;

      // --- Health ---
      if (method === 'GET' && path === '/health') {
        response = handleHealth(env);
        return addSecurityHeaders(response);
      }

      // --- JWKS (public key for JWT verification) ---
      if (method === 'GET' && path === '/.well-known/jwks.json') {
        response = await handleJWKS(env);
        return addSecurityHeaders(response);
      }

      // --- Pages ---
      if (method === 'GET' && path === '/login') {
        response = await handleLoginPage(request, env);
        return addSecurityHeaders(response);
      }

      if (method === 'GET' && path === '/register') {
        response = await handleRegisterPage(request, env);
        return addSecurityHeaders(response);
      }

      if (method === 'GET' && path === '/reset-password') {
        response = await handleResetPasswordPage(request, env);
        return addSecurityHeaders(response);
      }

      // --- API endpoints ---
      if (method === 'POST' && path === '/api/register') {
        response = await handleRegister(request, env);
        await logAuthEvent(env, {
          event: 'register_attempt',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
          statusCode: response.status,
        });
        return addSecurityHeaders(response);
      }

      if (method === 'POST' && path === '/api/login') {
        response = await handleLogin(request, env);
        await logAuthEvent(env, {
          event: response.status === 302 && response.headers.get('Location')?.includes('error=') ? 'login_failure' : 'login_attempt',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
          statusCode: response.status,
        });
        return addSecurityHeaders(response);
      }

      if (method === 'POST' && path === '/api/token') {
        response = await handleTokenExchange(request, env);
        return addSecurityHeaders(response);
      }

      if (method === 'GET' && path === '/api/refresh') {
        response = await handleRefresh(request, env);
        return addSecurityHeaders(response);
      }

      if (method === 'POST' && path === '/api/logout') {
        response = await handleLogout(request, env);
        await logAuthEvent(env, {
          event: 'logout',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
        });
        return addSecurityHeaders(response);
      }

      if (method === 'POST' && path === '/api/logout-all') {
        response = await handleLogoutAll(request, env);
        await logAuthEvent(env, {
          event: 'logout_all',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
        });
        return addSecurityHeaders(response);
      }

      if (method === 'POST' && path === '/api/forgot-password') {
        response = await handleForgotPassword(request, env);
        await logAuthEvent(env, {
          event: 'forgot_password',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
        });
        return addSecurityHeaders(response);
      }

      if (method === 'POST' && path === '/api/reset-password') {
        response = await handleResetPassword(request, env);
        await logAuthEvent(env, {
          event: response.headers.get('Location')?.includes('error=') ? 'password_reset_failure' : 'password_reset_success',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
          statusCode: response.status,
        });
        return addSecurityHeaders(response);
      }

      // --- OAuth initiation routes ---
      if (method === 'GET' && path === '/oauth/google') {
        response = await handleGoogleOAuthInit(request, env);
        return addSecurityHeaders(response);
      }

      if (method === 'GET' && path === '/oauth/facebook') {
        response = await handleFacebookOAuthInit(request, env);
        return addSecurityHeaders(response);
      }

      if (method === 'GET' && path === '/oauth/apple') {
        response = await handleAppleOAuthInit(request, env);
        return addSecurityHeaders(response);
      }

      if (method === 'GET' && path === '/oauth/microsoft') {
        response = await handleMicrosoftOAuthInit(request, env);
        return addSecurityHeaders(response);
      }

      // --- OAuth callback routes ---
      if (method === 'GET' && path === '/oauth/google/callback') {
        response = await handleGoogleOAuthCallback(request, env);
        await logAuthEvent(env, {
          event: 'oauth_callback',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
          details: { provider: 'google' },
        });
        return addSecurityHeaders(response);
      }

      if (method === 'GET' && path === '/oauth/facebook/callback') {
        response = await handleFacebookOAuthCallback(request, env);
        await logAuthEvent(env, {
          event: 'oauth_callback',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
          details: { provider: 'facebook' },
        });
        return addSecurityHeaders(response);
      }

      // Apple uses form POST for callbacks (response_mode: form_post)
      if (method === 'POST' && path === '/oauth/apple/callback') {
        response = await handleAppleOAuthCallback(request, env);
        await logAuthEvent(env, {
          event: 'oauth_callback',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
          details: { provider: 'apple' },
        });
        return addSecurityHeaders(response);
      }

      if (method === 'GET' && path === '/oauth/microsoft/callback') {
        response = await handleMicrosoftOAuthCallback(request, env);
        await logAuthEvent(env, {
          event: 'oauth_callback',
          ip: clientIp,
          route: path,
          userAgent: request.headers.get('User-Agent'),
          details: { provider: 'microsoft' },
        });
        return addSecurityHeaders(response);
      }

      // --- 404 ---
      return addSecurityHeaders(new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }));
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Internal server error';
      console.error('Auth Worker error:', message);
      return addSecurityHeaders(new Response(JSON.stringify({ error: 'Internal server error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }));
    }
  },
} satisfies ExportedHandler<Env>;
