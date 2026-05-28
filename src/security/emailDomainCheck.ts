/**
 * Platform-role email domain check.
 *
 * The platform role (`__platform__` membership) is restricted to users whose
 * email domain appears in `PLATFORM_OWNER_EMAIL_DOMAINS` (comma-separated env
 * var). This keeps the check data-driven — staging and production carry
 * different values without any per-environment code branches.
 *
 * Production env var value:  "centerpiecelab.com"
 * Staging env var value:     "centerpiecelab.com,centerpiecelab.dev"
 */
import type { Env } from '../types.js';

/**
 * Return true if `email` ends with `@<domain>` for any domain listed in
 * `env.PLATFORM_OWNER_EMAIL_DOMAINS`. An empty or missing env var rejects all
 * emails (fail-closed).
 */
export function isPlatformEmailAllowed(email: string, env: Env): boolean {
  const raw = env.PLATFORM_OWNER_EMAIL_DOMAINS ?? '';
  const domains = raw
    .split(',')
    .map(d => d.trim())
    .filter(d => d.length > 0);

  if (domains.length === 0) return false;

  return domains.some(domain => email.endsWith('@' + domain));
}
