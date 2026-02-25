/**
 * Cloudflare Worker environment bindings for centerpiece-auth.
 */
export interface Env {
  // D1 Database
  AUTH_DB: D1Database;

  // KV Namespaces (read-only — tenant branding lookups)
  CANONICAL_INPUTS: KVNamespace;
  TENANT_CONFIGS: KVNamespace;

  // Environment variables
  ENVIRONMENT: string;
  AUTH_DOMAIN: string;
  ACCESS_TOKEN_TTL_SECONDS: string;
  REFRESH_TOKEN_TTL_DAYS: string;
  AUTH_CODE_TTL_SECONDS: string;

  // Secrets (JWT signing)
  JWT_PRIVATE_KEY: string;   // Base64-encoded ES256 PEM private key
  JWT_PUBLIC_KEY: string;    // Base64-encoded ES256 PEM public key

  // Secrets (Email — Phase 1B.3)
  SENDGRID_API_KEY?: string;  // Optional: email delivery disabled if not set

  // Environment variables (Email — Phase 1B.3)
  EMAIL_FROM: string;
  EMAIL_FROM_NAME: string;

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
