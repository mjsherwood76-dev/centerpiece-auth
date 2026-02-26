/**
 * Build-time metadata injected via esbuild `define` config.
 * Falls back to 'dev' / current timestamp when running outside esbuild (local dev, tests).
 */

export const BUILD_SHA: string =
  typeof __BUILD_SHA__ !== 'undefined' ? __BUILD_SHA__ : 'dev';

export const BUILD_TIMESTAMP: string =
  typeof __BUILD_TIMESTAMP__ !== 'undefined' ? __BUILD_TIMESTAMP__ : new Date().toISOString();

export const BUILD_ENV: string =
  typeof __BUILD_ENV__ !== 'undefined' ? __BUILD_ENV__ : 'development';
