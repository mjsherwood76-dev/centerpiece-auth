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
| `/oauth/{provider}` | GET | Initiate OAuth flow |
| `/oauth/{provider}/callback` | GET/POST | OAuth callback |

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

### JWT Signing
- ES256 (ECDSA P-256) — asymmetric
- Auth Worker signs with private key
- Runtime verifies with public key (fetched from JWKS endpoint)
- `kid: "v1"` header for future key rotation

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
```

---

## Document Authority

This document describes ONLY what exists today in `centerpiece-auth`.
It does not speculate about future sessions or unimplemented features.
For platform-wide architecture, see `centerpiece/ARCHITECTURE.md`.
