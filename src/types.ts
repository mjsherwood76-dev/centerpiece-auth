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

  // Secrets (OAuth providers — wired in Session 4)
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  FACEBOOK_APP_ID?: string;
  FACEBOOK_APP_SECRET?: string;
  APPLE_CLIENT_ID?: string;
  APPLE_CLIENT_SECRET?: string;
  APPLE_KEY_ID?: string;
  APPLE_TEAM_ID?: string;
  APPLE_PRIVATE_KEY?: string;
  MICROSOFT_CLIENT_ID?: string;
  MICROSOFT_CLIENT_SECRET?: string;
}
