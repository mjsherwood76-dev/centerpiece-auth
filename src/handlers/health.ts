/**
 * GET /health — simple health check endpoint.
 */
import type { Env } from '../types.js';

export function handleHealth(env: Env): Response {
  return new Response(
    JSON.stringify({
      status: 'ok',
      service: 'centerpiece-auth',
      environment: env.ENVIRONMENT,
      timestamp: new Date().toISOString(),
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    }
  );
}
