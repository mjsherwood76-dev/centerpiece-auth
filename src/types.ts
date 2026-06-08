/**
 * Cloudflare Worker environment bindings for centerpiece-auth.
 */
export interface Env {
  // D1 Database
  AUTH_DB: D1Database;

  // D1 Database (read-only — tenant name/domain lookups)
  TENANTS_DB: D1Database;

  // KV Namespaces (read-only — tenant branding lookups)
  CANONICAL_INPUTS: KVNamespace;
  TENANT_CONFIGS: KVNamespace;

  // Shared rate-limit KV (Phase 3.12) — sliding-window counters for the shared
  // RateLimiter from @centerpiece/site-compositor/security.
  RATE_LIMIT_KV: KVNamespace;

  // Analytics Engine dataset (Phase 3.12) — receives `rate_limit_hit` events
  // for cross-Worker abuse-detection correlation. Shared dataset name across
  // all public Workers.
  ANALYTICS: AnalyticsEngineDataset;

  // Service Bindings
  // PLATFORM_API is a fetch-capable Cloudflare Worker service binding to
  // centerpiece-platform-api. Auth calls the internal transactional email
  // route via `binding.fetch()` — see src/email/platformApiClient.ts.
  PLATFORM_API?: import('./email/platformApiClient.js').PlatformApiEmailBinding;

  // Operator-only emergency rollback flag for the transactional SendGrid
  // fallback path. The provider split (Phase 3.10) requires Cloudflare
  // Email Sending via platform-api for transactional email; SendGrid is
  // only reachable when this is explicitly set to 'true'.
  ALLOW_TRANSACTIONAL_SENDGRID_ROLLBACK?: string;

  // Environment variables
  ENVIRONMENT: string;
  AUTH_DOMAIN: string;
  ACCESS_TOKEN_TTL_SECONDS: string;
  REFRESH_TOKEN_TTL_DAYS: string;
  REFRESH_TOKEN_TTL_DAYS_REMEMBERED: string;
  AUTH_CODE_TTL_SECONDS: string;

  // Tenant id used for transactional emails sent outside any tenant storefront
  // context (platform-admin password reset on hub.centerpiecelab.com). Must
  // reference an existing row in TENANTS_DB.tenants.
  PLATFORM_TENANT_ID: string;

  // Secrets (JWT signing)
  JWT_PRIVATE_KEY: string;   // Base64-encoded ES256 PEM private key
  JWT_PUBLIC_KEY: string;    // Base64-encoded ES256 PEM public key

  // Secrets (Email — Phase 1B.3)
  SENDGRID_API_KEY?: string;  // Optional: email delivery disabled if not set

  // Environment variables (Email — Phase 1B.3)
  EMAIL_FROM: string;
  EMAIL_FROM_NAME: string;

  // Secret for internal service-to-service calls (e.g. runtime → auth)
  INTERNAL_SECRET?: string;

  // Comma-separated list of allowed email domains for the platform role.
  // Production: "centerpiecelab.com"
  // Staging:    "centerpiecelab.com,centerpiecelab.dev"
  PLATFORM_OWNER_EMAIL_DOMAINS: string;

  // Platform domain for legal footer links (privacy / terms / cookies).
  // Production: "centerpiecelab.com"  Staging: "centerpiecelab.dev"
  PLATFORM_DOMAIN: string;

  // Canonical issuer URL for OAuth Authorization Server Metadata (RFC 8414).
  // Production: "https://auth.centerpiecelab.com"
  // Staging:    "https://auth.centerpiecelab.dev"
  AUTH_ISSUER_URL: string;

  // Feature flag: set to 'false' or '0' to disable the HIBP breach check
  // without a redeploy. Absent or any other value = enabled (default).
  PASSWORD_BREACH_CHECK_ENABLED?: string;

  // Secrets (OAuth providers)
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
}
