/**
 * Hostnames that serve the Centerpiece admin console.
 * Used to determine audience ('admin' vs 'storefront') during auth flows.
 *
 * Note: `staging.centerpiecelab.com` was the legacy staging admin custom domain;
 * it was decommissioned 2026-05-18 (Fix_Staging_Zone_Separation). Staging admin
 * now lives at `hub.centerpiecelab.dev` (custom domain) and
 * `centerpiece-platform-ui-staging.pages.dev` (fallback).
 */
export const ADMIN_DOMAINS: readonly string[] = [
  'hub.centerpiecelab.com',
  'hub.centerpiecelab.dev',
  'centerpiece-platform-ui-staging.pages.dev',
];

/**
 * Check if a hostname is an admin console domain.
 */
export function isAdminDomain(hostname: string): boolean {
  return ADMIN_DOMAINS.includes(hostname);
}

/**
 * Domain suffixes controlled by the Centerpiece platform.
 * Used for CORS origin validation and redirect URL validation.
 *
 * SECURITY: this list must contain ONLY suffixes where every possible
 * subdomain is platform-controlled. Public deploy suffixes (`.workers.dev`,
 * `.pages.dev`) were removed 2026-06-10 (codebase review C1/H1): anyone can
 * deploy under them, so treating them as controlled created an open redirect
 * (auth-code theft) and credentialed-CORS reflection for attacker origins.
 * Specific platform hosts on those suffixes belong in CONTROLLED_HOSTS.
 */
export const CONTROLLED_SUFFIXES: readonly string[] = [
  '.centerpiece.shop',
  '.centerpiece.app',
  '.centerpiece.io',
  '.centerpiecelab.com',
  '.centerpiecelab.dev',
];

/**
 * Exact platform-controlled hostnames that live on PUBLIC deploy suffixes
 * (`workers.dev` / `pages.dev` fallbacks). Exact-match only — never add a
 * suffix here.
 */
export const CONTROLLED_HOSTS: readonly string[] = [
  'centerpiece-platform-ui-staging.pages.dev',
  'centerpiece-site-runtime-staging.mjsherwood76.workers.dev',
  'centerpiece-auth-staging.mjsherwood76.workers.dev',
];

/**
 * Check if a hostname is platform-controlled: an exact controlled host, or
 * any subdomain of a controlled suffix.
 */
export function isControlledHostname(hostname: string): boolean {
  if (CONTROLLED_HOSTS.includes(hostname)) return true;
  return CONTROLLED_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}