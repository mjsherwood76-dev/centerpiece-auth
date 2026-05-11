# CLAUDE.md — centerpiece-auth

Session quickref. **Authority: workspace `AI_RULES.md` wins; this repo's `AI_RULES.md` is next.**

## Purpose

Centralized **identity provider** Worker. Email/password registration & login, OAuth (Google/Facebook/Apple/Microsoft), JWT (ES256) issuance with JWKS endpoint, refresh-token rotation with theft detection, password reset, tenant-branded login/register pages.

- Production: `auth.centerpiecelab.com`
- Staging: `centerpiece-auth-staging.mjsherwood76.workers.dev`

Runtime ↔ auth are **HTTP peers** — neither imports code from the other.

## Stack

TypeScript • Cloudflare Workers • esbuild • node:test via tsx • PBKDF2-SHA-256 (100k iterations) for passwords • ES256 JWTs.

## Commands

| Command | Purpose |
|---|---|
| `npm run build` / `build:worker` | esbuild → `dist/worker.js` |
| `npm run dev` | `wrangler dev dist/worker.js --port 8788` (rare; staging is dev env) |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | `tsx --test test/**/*.test.ts` |
| `npm run deploy` | Production deploy |
| `npm run deploy:staging` | Staging deploy |
| `npm run db:migrate:local` | D1 migration against `--local` |
| `npm run db:migrate:staging` | D1 migration against staging env |
| `npm run db:migrate:prod` | D1 migration against production |

Workspace-root delegations: `deploy:staging:auth`, `deploy:production:auth`.

## Important files (from `AI_RULES.md`)

```
src/
├── worker.ts                  # entry + router
├── types.ts                   # Env interface
├── db.ts                      # D1 abstraction
├── branding.ts                # tenant branding loader (KV)
├── crypto/
│   ├── passwords.ts           # PBKDF2-SHA-256 (100k iters)
│   ├── jwt.ts                 # sign + verify (ES256)
│   └── refreshTokens.ts       # generate + rotate
├── security/
│   ├── redirectValidator.ts   # redirect URL validation (security boundary)
│   ├── rateLimit.ts           # per-IP via KV
│   ├── headers.ts             # security headers + CORS
│   └── auditLog.ts            # structured audit logging
├── handlers/                  # health, jwks, register, login, token, refresh,
│                              # logout, forgotPassword, resetPassword,
│                              # memberships, internalMemberships, internalUsers,
│                              # customers
├── oauth/                     # base, callback, google, facebook, apple, microsoft
└── pages/                     # renderer, login, register, resetPassword
migrations/                    # D1 schema (0001_initial_schema.sql, …)
```

## Bindings & env (from `wrangler.toml`)

**D1**: `AUTH_DB` (`centerpiece-auth-db`), `TENANTS_DB` (read-only — name/domain lookups)
**KV**: `CANONICAL_INPUTS` (read-only), `TENANT_CONFIGS` (read-only)
**Service Binding**: `PLATFORM_API` (entrypoint `PlatformApiService`)

**Vars**: `ENVIRONMENT`, `AUTH_DOMAIN`, `EMAIL_FROM=noreply@centerpiecelab.com`, `EMAIL_FROM_NAME=Centerpiece Lab`, `ACCESS_TOKEN_TTL_SECONDS=900` (15 min), `REFRESH_TOKEN_TTL_DAYS=30`, `AUTH_CODE_TTL_SECONDS=60`.

**Secrets** (`wrangler secret put`): `JWT_PRIVATE_KEY` & `JWT_PUBLIC_KEY` (ES256 PEM, base64-encoded), `INTERNAL_SECRET`, `GOOGLE_CLIENT_ID/SECRET`, `FACEBOOK_APP_ID/SECRET`, `APPLE_CLIENT_ID/SECRET/KEY_ID/TEAM_ID/PRIVATE_KEY` (PEM b64), `MICROSOFT_CLIENT_ID/SECRET`, `SENDGRID_API_KEY` (Mail Send only).

## Routes

Production: `auth.centerpiecelab.com/*` on zone `centerpiecelab.com`.
Staging: `routes = []` → `*.workers.dev`.

## Deploy rules

- D1 migrations are **not** auto-applied by deploy. Run `db:migrate:staging` then `db:migrate:prod` explicitly when migrations change.
- DNS for `auth.centerpiecelab.com` must exist (CNAME/A, proxied) before production routes work.

## Test rules

- `node:test` via tsx.
- Tests cover: health, headers, pages, register, login, token-exchange, password-reset, jwks, redirect-validation.

## Danger zones (from repo `AI_RULES.md`)

- **Redirect validation is non-negotiable.** Every redirect-producing handler must call `redirectValidator.ts`. Require `https:` (allow `http:` only for localhost in dev). Hostname must be a known tenant domain or controlled suffix. Reject IP literals, fragments, `javascript:` URIs.
- **Tenant scoping**: `tenant` query param is a branding hint only — not a trust boundary. Derive authoritative `tenant_id` from the redirect URL hostname. Mismatch → reject.
- **Auto-created memberships**: ONLY context `customer` (sub_role NULL) — NEVER `seller`/`supplier`/`platform`.
- **Account enumeration prevention**: login failure is always `"Invalid email or password"`. Forgot-password is always `"If that email exists, we sent a reset link"`.
- **OAuth email linking**: only auto-link when provider confirms `email_verified === true`; unverified email → create separate user.
- **Token security**: never store plaintext auth codes / refresh tokens / reset tokens — always SHA-256 hashes. Refresh-token rotation with reuse/theft detection. JWTs ES256 (asymmetric); no shared secrets.
- **D1**: run `PRAGMA foreign_keys = ON` on every connection; use prepared statements; constant-time comparison for token/hash checks.
- **Don't import** from `centerpiece-site-runtime` (or any sibling code repo) or from `mjs76-dev-standards`.
- **Don't hardcode** tenant IDs or domains.

## Pointers

- `AI_RULES.md` — authoritative repo rules
- `ARCHITECTURE.md` (~391 lines)
- Workspace `AI_RULES.md` — wins over this repo's
