/**
 * GET /health — health check endpoint with build version and D1 probe.
 */
import type { Env } from '../types.js';
import { BUILD_SHA, BUILD_TIMESTAMP, BUILD_ENV } from '../core/buildInfo.js';

export async function handleHealth(env: Env, correlationId?: string): Promise<Response> {
  const checksStart = Date.now();
  const subsystems: Record<string, { status: 'ok' | 'error'; latencyMs: number; error?: string }> = {};

  // ── D1 probe ──────────────────────────────────────────
  const d1Start = Date.now();
  try {
    await env.AUTH_DB.prepare('SELECT 1').first();
    subsystems.d1 = { status: 'ok', latencyMs: Date.now() - d1Start };
  } catch (err) {
    subsystems.d1 = {
      status: 'error',
      latencyMs: Date.now() - d1Start,
      error: err instanceof Error ? err.message : 'D1 query failed',
    };
  }

  const hasError = Object.values(subsystems).some(s => s.status === 'error');

  return new Response(
    JSON.stringify({
      status: hasError ? 'degraded' : 'ok',
      service: 'centerpiece-auth',
      version: BUILD_SHA,
      env: BUILD_ENV,
      deployedAt: BUILD_TIMESTAMP,
      environment: env.ENVIRONMENT,
      timestamp: new Date().toISOString(),
      correlationId: correlationId || null,
      subsystems,
      durationMs: Date.now() - checksStart,
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    },
  );
}
