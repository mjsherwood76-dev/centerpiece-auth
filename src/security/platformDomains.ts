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
 */
export const CONTROLLED_SUFFIXES: readonly string[] = [
  '.centerpiece.shop',
  '.centerpiece.app',
  '.centerpiece.io',
  '.centerpiecelab.com',
  '.centerpiecelab.dev',
  '.workers.dev',
  '.pages.dev',
];