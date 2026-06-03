/**
 * GET /.well-known/oauth-authorization-server
 *
 * RFC 8414 Authorization Server Metadata endpoint.
 * Returned by discovery clients (Phase 5.7 MCP server, third-party integrations)
 * to learn about this server's OAuth capabilities.
 *
 * This endpoint is intentionally unauthenticated — it is public metadata.
 */
import type { Env } from '../types.js';

export function handleWellKnownOauth(env: Env): Response {
  const issuer = env.AUTH_ISSUER_URL;

  const metadata = {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: null,
    scopes_supported: [
      'openid',
      'profile',
      'email',
      'tenant:read',
      'tenant:write',
      'orders:read',
      'orders:write',
    ],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    service_documentation: 'https://centerpiecelab.com/developers/oauth',
  };

  return new Response(JSON.stringify(metadata), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
