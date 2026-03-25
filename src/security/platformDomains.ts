/**
 * Hostnames that serve the Centerpiece admin console.
 * Used to determine audience ('admin' vs 'storefront') during auth flows.
 */
export const ADMIN_DOMAINS: readonly string[] = [
  'hub.centerpiecelab.com',
  'staging.centerpiecelab.com',
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
  '.workers.dev',
  '.pages.dev',
];