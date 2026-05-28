/**
 * Device Label and Fingerprint Helpers
 *
 * Used at refresh-token issuance time (login, register, oauth/callback) to
 * capture a human-readable device label and a stable device fingerprint for
 * display in the "Active Sessions" tab (S4).
 *
 * No external dependencies — zero-dep inline regex for the 6 browsers and
 * 5 OSes that cover >99% of admin traffic. Falls back to "Unknown browser"
 * for unmatched UA strings. device_label is advisory display-only and is
 * never used for security decisions.
 *
 * device_fingerprint = sha256Hex(ua + '|' + cfCountry)
 *   Country only — NOT city. City changes with travel within a country or
 *   VPN region; country is more stable. The trade-off: a user travelling
 *   internationally will generate a new fingerprint.
 */
import { sha256Hex } from '../crypto/jwt.js';

// ─── OS Detection ────────────────────────────────────────────

/**
 * Map a User-Agent string to a display-friendly OS name.
 * Order matters — more specific patterns must precede broader ones.
 */
function detectOS(ua: string): string {
  if (/iPhone|iPad|iPod/.test(ua)) return 'iOS';
  if (/Android/.test(ua)) return 'Android';
  if (/Windows NT/.test(ua)) return 'Windows';
  if (/Mac OS X/.test(ua)) return 'macOS';
  if (/Linux/.test(ua)) return 'Linux';
  return 'Unknown OS';
}

// ─── Browser Detection ───────────────────────────────────────

/**
 * Map a User-Agent string to a display-friendly browser name + major version.
 * Order matters — Edge/OPR must precede Chrome because their UAs contain "Chrome".
 */
function detectBrowser(ua: string): string {
  // Edge (Chromium-based)
  const edgeMatch = ua.match(/Edg\/(\d+)/);
  if (edgeMatch) return `Edge ${edgeMatch[1]}`;

  // Opera (Chromium-based)
  const oprMatch = ua.match(/OPR\/(\d+)/);
  if (oprMatch) return `Opera ${oprMatch[1]}`;

  // Samsung Internet
  const samsungMatch = ua.match(/SamsungBrowser\/(\d+)/);
  if (samsungMatch) return `Samsung Browser ${samsungMatch[1]}`;

  // Chrome / Chromium
  const chromeMatch = ua.match(/Chrome\/(\d+)/);
  if (chromeMatch) return `Chrome ${chromeMatch[1]}`;

  // Safari (must come after Chrome — Chrome UA also contains "Safari")
  const safariMatch = ua.match(/Version\/(\d+).*Safari/);
  if (safariMatch) return `Safari ${safariMatch[1]}`;

  // Firefox
  const firefoxMatch = ua.match(/Firefox\/(\d+)/);
  if (firefoxMatch) return `Firefox ${firefoxMatch[1]}`;

  return 'Unknown browser';
}

// ─── Public API ──────────────────────────────────────────────

/**
 * Build a human-readable device label from a User-Agent string.
 *
 * Output format: "{Browser} {version} on {OS}" — e.g. "Chrome 120 on macOS".
 * Falls back to "Unknown browser" for unmatched UA strings.
 *
 * @param ua - The User-Agent request header value (may be null/empty)
 */
export function buildDeviceLabel(ua: string | null | undefined): string {
  if (!ua) return 'Unknown browser';
  const browser = detectBrowser(ua);
  const os = detectOS(ua);
  return `${browser} on ${os}`;
}

/**
 * Compute a stable device fingerprint from the UA string and Cloudflare
 * country header value.
 *
 * fingerprint = sha256Hex(ua + '|' + country)
 *
 * Country only (not city): stable across travel within a country and across
 * most VPN exit nodes. Changes when the user travels internationally.
 *
 * @param ua      - User-Agent string (null → treated as empty string)
 * @param country - Cloudflare CF-IPCountry header value, e.g. "US" (null → '')
 */
export async function buildDeviceFingerprint(
  ua: string | null | undefined,
  country: string | null | undefined
): Promise<string> {
  const uaNorm = ua ?? '';
  const countryNorm = country ?? '';
  return sha256Hex(`${uaNorm}|${countryNorm}`);
}
