/**
 * esbuild build configuration for centerpiece-auth Worker.
 *
 * Injects build-time constants (__BUILD_SHA__, __BUILD_TIMESTAMP__, __BUILD_ENV__)
 * via esbuild `define` for health endpoint and structured logging.
 */
import { execSync } from 'child_process';
import { build } from 'esbuild';

let buildSha;
try {
  buildSha = execSync('git rev-parse --short HEAD').toString().trim();
} catch {
  buildSha = process.env.GIT_SHA ?? 'unknown';
}

const buildTimestamp = new Date().toISOString();
const buildEnv = process.env.WORKERS_ENV ?? 'development';

await build({
  entryPoints: ['src/worker.ts'],
  bundle: true,
  format: 'esm',
  outfile: 'dist/worker.js',
  platform: 'browser',
  target: 'es2022',
  external: ['node:*'],
  define: {
    '__BUILD_SHA__': JSON.stringify(buildSha),
    '__BUILD_TIMESTAMP__': JSON.stringify(buildTimestamp),
    '__BUILD_ENV__': JSON.stringify(buildEnv),
  },
});

console.log(`Built auth worker: sha=${buildSha} env=${buildEnv} at=${buildTimestamp}`);
