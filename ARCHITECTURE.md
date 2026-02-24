# Centerpiece Auth — Architecture

> **Scope:** This document covers the `centerpiece-auth` Worker only.
> For the full platform architecture, see `centerpiece/ARCHITECTURE.md`.

---

## Overview

`centerpiece-auth` is a Cloudflare Worker that serves as the centralized identity
provider for the Centerpiece platform. It is deployed at `auth.centerpiecelab.com`
and handles all authentication and authorization concerns.

### Core Properties

| Property | Value |
|----------|-------|
| **Deployment** | Cloudflare Worker |
| **Domain** | `auth.centerpiecelab.com` (prod) |
| **Database** | Cloudflare D1 (SQLite) |
| **JWT Algorithm** | ES256 (ECDSA P-256) |
| **Token Model** | Short-lived JWT + HttpOnly refresh cookie |
| **Identity Model** | Platform-wide users + tenant-scoped memberships |

---

## Identity Model (FD-1)

```
┌──────────────────────┐
│       users          │  ← Platform-wide identity
│  (email, name, hash) │
└──────────┬───────────┘
           │ 1:N
           ▼
┌──────────────────────┐
│  tenant_memberships  │  ← Per-tenant authorization
│  (userId, tenantId,  │
│   role, status)      │
└──────────────────────┘
```

- One user can be a customer at Store A and a seller at Store B.
- Roles: `customer`, `seller`, `platform_admin`.
- Only `customer` role is auto-created; others require explicit invitation.

---

## Auth Flow (FD-4)

```
                        ┌──────────────────────────┐
                        │   Storefront Runtime     │
                        │  (tenant domain)         │
                        └──────────┬───────────────┘
                                   │
                          1. Redirect to auth domain
                                   │
                                   ▼
                        ┌──────────────────────────┐
                        │   Auth Worker            │
                        │  (auth.centerpiecelab.com)│
                        │                          │
                        │  Login / Register / OAuth │
                        └──────────┬───────────────┘
                                   │
                          2. Issue refresh cookie (on auth domain)
                          3. Redirect back with one-time auth code
                                   │
                                   ▼
                        ┌──────────────────────────┐
                        │   Storefront Runtime     │
                        │  /auth/callback?code=... │
                        │                          │
                        │  4. Exchange code → JWT  │
                        │     (server-to-server)   │
                        │  5. Set cp_access cookie │
                        │     (on tenant domain)   │
                        └──────────────────────────┘
```

### Token Details

| Token | TTL | Storage | Scope |
|-------|-----|---------|-------|
| Access (JWT) | 15 min | `cp_access` HttpOnly cookie on tenant domain | `aud: storefront \| admin` |
| Refresh | 30 days | HttpOnly cookie on auth domain (`SameSite=Lax`) | Auth domain only |
| Auth Code | 60 sec | D1 (hash stored, single-use) | One-time exchange |

### Refresh Flow

On expired JWT, the runtime performs a **top-level redirect** to the auth domain's
refresh endpoint. The refresh cookie travels naturally (SameSite=Lax allows top-level
navigation). Auth Worker validates, rotates the refresh token, issues a new auth code,
and redirects back. This is Safari/iOS compatible (no third-party cookie dependency).

---

## Database Schema

### Tables

| Table | Purpose |
|-------|---------|
| `users` | Platform-wide user identity |
| `tenant_memberships` | Per-tenant authorization (userId + tenantId + role) |
| `oauth_accounts` | Linked OAuth provider accounts |
| `auth_codes` | Single-use authorization codes (hash stored) |
| `refresh_tokens` | Refresh token tracking with family-based rotation |
| `oauth_states` | CSRF protection for OAuth flows |
| `password_reset_tokens` | Password reset tokens (hash stored) |

### Critical Constraints

- `PRAGMA foreign_keys = ON` must run per-connection (D1/SQLite requirement)
- All tokens stored as SHA-256 hashes — never plaintext
- `tenant_memberships` has `UNIQUE(user_id, tenant_id)` constraint
- `oauth_accounts` has `UNIQUE(provider, provider_account_id)` constraint

---

## KV Bindings (Read-Only)

| Binding | Purpose |
|---------|---------|
| `CANONICAL_INPUTS` | Theme tokens (brands, styles) for login page branding |
| `TENANT_CONFIGS` | Tenant configuration for domain validation and branding |

These are the SAME KV namespaces used by `centerpiece-site-runtime` — shared read-only.

---

## Route Map

### Health & Discovery
| Route | Method | Purpose |
|-------|--------|---------|
| `/health` | GET | Health check |
| `/.well-known/jwks.json` | GET | Public key for JWT verification |

### Pages (HTML — Session 2)
| Route | Method | Purpose |
|-------|--------|---------|
| `/login` | GET | Branded login page |
| `/register` | GET | Branded register page |
| `/reset-password` | GET | Branded password reset form |

### API (JSON — Session 3+)
| Route | Method | Purpose |
|-------|--------|---------|
| `/api/register` | POST | Email/password registration |
| `/api/login` | POST | Email/password login |
| `/api/token` | POST | Auth code → JWT exchange |
| `/api/refresh` | GET | Top-level redirect refresh |
| `/api/forgot-password` | POST | Request password reset |
| `/api/reset-password` | POST | Complete password reset |
| `/api/logout` | POST | Revoke single session |
| `/api/logout-all` | POST | Revoke all sessions |

### OAuth (Session 4)
| Route | Method | Purpose |
|-------|--------|---------|
| `/oauth/google` | GET | Initiate Google OAuth (OIDC, PKCE) |
| `/oauth/google/callback` | GET | Google OAuth callback |
| `/oauth/facebook` | GET | Initiate Facebook OAuth |
| `/oauth/facebook/callback` | GET | Facebook OAuth callback |
| `/oauth/apple` | GET | Initiate Apple OAuth (OIDC) |
| `/oauth/apple/callback` | POST | Apple OAuth callback (form_post) |
| `/oauth/microsoft` | GET | Initiate Microsoft OAuth (OIDC, PKCE) |
| `/oauth/microsoft/callback` | GET | Microsoft OAuth callback |

---

## Security Architecture

### Redirect Validation
All redirect-producing endpoints validate the target URL against:
1. Allowed schemes (`https:`, `http:` for dev localhost only)
2. Known tenant domains (from `TENANT_CONFIGS` KV)
3. Controlled suffixes (`*.centerpiece.shop`, `*.workers.dev`, etc.)
4. No IP literals, no fragments, no `javascript:` URIs

### Refresh Token Rotation
- Each refresh token belongs to a `family_id`
- On use: old token is revoked, new token is issued in the same family
- If a revoked token is presented → entire family is revoked (theft detection)

### Password Hashing
- PBKDF2-SHA-256 via Web Crypto API (`crypto.subtle`)
- **100,000 iterations** (Cloudflare Workers maximum; combined with 32-byte random salts)
- Format: `pbkdf2:{iterations}:{salt_hex}:{hash_hex}`
- Constant-time verification using XOR comparison

### Rate Limiting
- Per-IP rate limits using KV counters (not D1 — KV is faster for hot-path writes)
- Key pattern: `ratelimit:{ip}:{route}:{window}`
- **Production:** 10 attempts per 15-minute window per IP per route
- **Staging:** 200 attempts per window (to support integration test runs)
- Rate-limited routes: `/api/login`, `/api/register`, `/api/forgot-password`, `/api/reset-password`
- Fail-open: if KV is unavailable, requests are allowed (availability over strictness)

### Security Headers
All responses include:
- `X-Frame-Options: DENY` (clickjacking prevention)
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
- `Content-Security-Policy` on HTML pages

### CORS
- CORS preflight (`OPTIONS`) validates `Origin` against controlled suffixes
- Only known origins receive `Access-Control-Allow-Origin`
- Allowed methods: `GET, POST, OPTIONS`
- Credentials: allowed

### Audit Logging
- Structured JSON `console.log` for every auth event (for Cloudflare Logpush)
- Events: `register_attempt`, `login_attempt`, `login_failure`, `logout`, `logout_all`,
  `forgot_password`, `password_reset_success`, `password_reset_failure`,
  `rate_limit_exceeded`, `oauth_callback`
- Includes: IP, route, User-Agent, status code, timestamp

### Password Reset Flow
1. `POST /api/forgot-password` → generates random token, stores SHA-256 hash in D1
2. (Stub) Logs reset URL to console (real email delivery in Phase 1B.3)
3. Always returns generic success (account enumeration prevention)
4. `POST /api/reset-password` → validates token hash + expiration, updates password, revokes all refresh tokens

### JWT Signing
- ES256 (ECDSA P-256) — asymmetric
- Auth Worker signs with private key
- Runtime verifies with public key (fetched from JWKS endpoint)
- `kid: "v1"` header for future key rotation

### OAuth Architecture

**Providers:** Google, Facebook, Apple, Microsoft

**Flow:**
1. User clicks OAuth button → `GET /oauth/{provider}?tenant=...&redirect=...`
2. Auth Worker validates redirect URL, creates state entry in D1 (PKCE + nonce + 5-min TTL)
3. Redirects to provider's authorization page
4. Provider authenticates user, redirects to callback URL with authorization code
5. Auth Worker validates state (CSRF protection), exchanges code for tokens
6. Parses/validates provider's ID token (iss, aud, exp, nonce)
7. Resolves user: find by OAuth link → find by email (if verified) → create new
8. Issues refresh token + authorization code, redirects to tenant

**PKCE:** Code verifier + S256 challenge for Google and Microsoft. Facebook and Apple
do not support PKCE but we store verifiers for consistency.

**Email Linking Rules:**
- Provider confirms `email_verified === true` → link to existing user with same email
- Provider does NOT verify email → create separate user (prevents account takeover)
- Apple: email always verified; name only on first login

**State Storage:** `oauth_states` D1 table with 5-minute TTL, consumed on callback (single-use)

---

## Build & Deploy

```bash
# Install dependencies
npm install

# Build
npm run build

# Deploy to staging
npm run deploy:staging

# Deploy to production
npm run deploy

# Run D1 migration
npm run db:migrate:staging

# Run integration tests (against staging)
npm test
```

---

## Testing

Integration tests run against the live staging Worker. **No local mocks.**

- **Framework:** `node --test` via `tsx`
- **Tests:** `test/**/*.test.ts` — HTTP requests to `https://centerpiece-auth-staging.mjsherwood76.workers.dev`
- **Coverage:** 52 tests across health, security headers, CORS, pages, register, login, token exchange, password reset, JWKS, redirect validation

Test files:
| File | Tests | Area |
|------|-------|------|
| `health-and-headers.test.ts` | 10 | Health, security headers, CORS, 404 |
| `pages.test.ts` | 7 | Login, register, reset-password page rendering |
| `register.test.ts` | 7 | Registration flow |
| `login.test.ts` | 5 | Login flow |
| `token-exchange.test.ts` | 6 | Code → JWT exchange |
| `password-reset.test.ts` | 7 | Forgot/reset password |
| `jwks.test.ts` | 2 | JWKS endpoint |
| `redirect-validation.test.ts` | 8 | Redirect URL validation |

---

## Document Authority

This document describes ONLY what exists today in `centerpiece-auth`.
It does not speculate about future sessions or unimplemented features.
For platform-wide architecture, see `centerpiece/ARCHITECTURE.md`.
