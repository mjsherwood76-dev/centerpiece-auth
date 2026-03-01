/**
 * Redirect URL Validation
 *
 * Validates redirect URLs to prevent open redirect attacks.
 *
 * Rules (from Security Principles):
 * - Parse as URL. Reject malformed URLs.
 * - Require https: scheme (allow http: only for localhost in dev).
 * - Require hostname to be a known tenant domain (lookup in TENANT_CONFIGS KV)
 *   or match a controlled suffix (*.centerpiece.shop, *.centerpiece.app,
 *   *.centerpiece.io, *.workers.dev for staging).
 * - Reject IP literals, fragments, and javascript: URIs.
 * - Store redirect_origin with the auth code and enforce match at exchange time.
 */

/** Controlled domain suffixes that are always accepted. */
const CONTROLLED_SUFFIXES = [
  '.centerpiece.shop',
  '.centerpiece.app',
  '.centerpiece.io',
  '.centerpiecelab.com',
  '.workers.dev',
  '.pages.dev',
];

/** Dev-only allowed origins (http localhost). */
const DEV_HOSTS = ['localhost', '127.0.0.1'];

export interface RedirectValidationResult {
  valid: boolean;
  origin: string;
  tenantId: string;
  error?: string;
}

/**
 * Validate a redirect URL against security rules.
 *
 * @param redirectUrl - The redirect URL to validate
 * @param tenantConfigs - KV namespace for tenant config lookups
 * @param environment - 'production' | 'staging' | 'preview' | 'development'
 */
export async function validateRedirectUrl(
  redirectUrl: string,
  tenantConfigs: KVNamespace,
  environment: string
): Promise<RedirectValidationResult> {
  const invalid = (error: string): RedirectValidationResult => ({
    valid: false,
    origin: '',
    tenantId: '',
    error,
  });

  // 1. Parse URL — reject malformed
  let url: URL;
  try {
    url = new URL(redirectUrl);
  } catch {
    return invalid('Malformed redirect URL');
  }

  // 2. Reject dangerous schemes
  if (url.protocol === 'javascript:') {
    return invalid('Rejected javascript: URI');
  }

  // 3. Require https: (allow http: for localhost in non-production)
  const isDev = environment !== 'production';
  if (url.protocol !== 'https:') {
    if (url.protocol === 'http:' && isDev && DEV_HOSTS.includes(url.hostname)) {
      // Allow http://localhost in dev/staging
    } else {
      return invalid('Redirect URL must use https:');
    }
  }

  // 4. Reject IP literals (except localhost in dev)
  const hostname = url.hostname;
  if (isIpLiteral(hostname) && !(isDev && DEV_HOSTS.includes(hostname))) {
    return invalid('IP literal hostnames are not allowed');
  }

  // 5. Reject fragments
  if (url.hash) {
    return invalid('Redirect URL must not contain fragments');
  }

  // 6. Check controlled suffixes — always allowed for any environment
  const isControlledDomain = CONTROLLED_SUFFIXES.some((suffix) =>
    hostname.endsWith(suffix)
  );

  // 7. Check localhost in dev
  const isDevLocalhost = isDev && DEV_HOSTS.includes(hostname);

  if (isControlledDomain || isDevLocalhost) {
    const origin = url.origin;
    // For controlled domains, try to derive tenant from the hostname
    // For now: use hostname prefix before first dot as a hint (not authoritative)
    const tenantId = await deriveTenantIdFromHostname(hostname, tenantConfigs);
    return { valid: true, origin, tenantId: tenantId || '__unknown__' };
  }

  // 8. Check known tenant domains in KV
  const tenantId = await lookupTenantByDomain(hostname, tenantConfigs);
  if (tenantId) {
    return { valid: true, origin: url.origin, tenantId };
  }

  return invalid(`Unknown redirect domain: ${hostname}`);
}

/**
 * Check if a hostname is an IP literal (IPv4 or IPv6).
 */
function isIpLiteral(hostname: string): boolean {
  // IPv6 bracket notation
  if (hostname.startsWith('[')) return true;
  // IPv4: all segments are numeric
  const parts = hostname.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p))) return true;
  return false;
}

/**
 * Look up a tenant ID from a custom domain in TENANT_CONFIGS KV.
 *
 * Convention: KV key `domain:{hostname}` → tenant config JSON with `id` field.
 */
async function lookupTenantByDomain(
  hostname: string,
  tenantConfigs: KVNamespace
): Promise<string | null> {
  try {
    const config = await tenantConfigs.get(`domain:${hostname}`, 'json') as { id?: string } | null;
    return config?.id ?? null;
  } catch {
    return null;
  }
}

/**
 * For controlled domains (*.workers.dev, *.centerpiece.shop, etc.),
 * attempt to derive the tenant ID from the hostname pattern.
 *
 * This is a branding hint only — the authoritative tenant comes from
 * the redirect_origin validated at code exchange time.
 */
async function deriveTenantIdFromHostname(
  hostname: string,
  tenantConfigs: KVNamespace
): Promise<string | null> {
  // First check if there's a direct domain mapping
  const direct = await lookupTenantByDomain(hostname, tenantConfigs);
  if (direct) return direct;

  // For *.workers.dev and *.pages.dev, the tenant might be embedded in the subdomain
  // This is best-effort — not authoritative
  return null;
}
