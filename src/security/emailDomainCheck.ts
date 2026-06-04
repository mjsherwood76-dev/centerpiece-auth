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

/**
 * Per-tenant domain-allowlist check (Phase 3.25 Tenant Access Gating).
 *
 * Generalizes the platform-owner check above for any tenant carrying a
 * `domain-allowlist` access policy. Returns true when `email`'s domain matches
 * one of `allowedEmailDomains` (lowercased bare domains, e.g. `valhallan.com`).
 *
 * Fail-closed: an empty/missing allowlist rejects every email. Callers MUST only
 * invoke this for GATED tenants — a public (ungated) tenant has no allowlist and
 * must remain open, so the caller short-circuits before reaching here.
 *
 * Matching mirrors `isPlatformEmailAllowed`: exact `@<domain>` suffix only, so a
 * subdomain (`x@sub.valhallan.com`) or prefix collision (`x@notvalhallan.com`)
 * does NOT pass. The email is lowercased before comparison.
 */
export function isEmailAllowedForTenant(
  email: string,
  allowedEmailDomains: readonly string[],
): boolean {
  const domains = allowedEmailDomains
    .map(d => d.trim().toLowerCase())
    .filter(d => d.length > 0);

  if (domains.length === 0) return false;

  const normalizedEmail = email.trim().toLowerCase();
  return domains.some(domain => normalizedEmail.endsWith('@' + domain));
}
