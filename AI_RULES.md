# AI RULES — centerpiece-auth

> **Authority**: This file is subordinate to `centerpiece/AI_RULES.md` (workspace root).
> If there is a conflict, the workspace-level rules win.

---

## Repository Purpose

`centerpiece-auth` is the **centralized identity provider** for the Centerpiece platform.
It is a standalone Cloudflare Worker (production: `auth.centerpiecelab.com`, staging: `centerpiece-auth-staging.mjsherwood76.workers.dev`) that handles:

- Email/password registration and login
- OAuth via Google, Facebook, Apple, Microsoft
- JWT (ES256) access token issuance
- Refresh token management with rotation and theft detection
- Password reset flows
- Tenant-branded login/register pages

---

## Ownership Boundary

### This Repo Owns

- User identity (the `users` table)
- Authentication flows (login, register, OAuth)
- Token lifecycle (JWT issuance, refresh rotation, revocation)
- Tenant membership records (`tenant_memberships`)
- Auth-specific page rendering (login, register, password reset)
- Redirect URL validation (security boundary)

### This Repo Does NOT Own

- Tenant configuration — read-only from `TENANT_CONFIGS` KV
- Theme definitions — read-only from `CANONICAL_INPUTS` KV
- Storefront rendering — belongs to `centerpiece-site-runtime`
- Admin UI — belongs to `centerpiece-platform-ui`
- Product/commerce data — belongs to runtime
- Email delivery infrastructure — uses SendGrid (API key as wrangler secret)

---

## Security Principles (NON-NEGOTIABLE)

### Redirect Validation
- All `redirect` parameters MUST be validated via `redirectValidator.ts`
- Require `https:` (allow `http:` only for localhost in dev)
- Hostname must be a known tenant domain or controlled suffix
- Reject IP literals, fragments, and `javascript:` URIs

### Tenant Validation
- `tenant` parameter is a branding hint only, not a trust boundary
- Derive authoritative `tenant_id` from the `redirect` URL hostname
- If `tenant` param mismatches derived tenant → reject

### Auto-Created Memberships
- ONLY create with context `customer` (sub_role NULL) — NEVER `seller`, `supplier`, or `platform`
- Only if tenant exists and allows self-serve customers

### Account Enumeration Prevention
- Login failure: always `"Invalid email or password"` — never reveal which failed
- Forgot password: always `"If that email exists, we sent a reset link"`

### OAuth Email Linking
- Only auto-link when provider confirms `email_verified === true`
- Unverified email → create separate user

### Token Security
- Never store plaintext auth codes, refresh tokens, or reset tokens
- Always store SHA-256 hashes
- Refresh token rotation with reuse/theft detection
- JWT signed with ES256 (asymmetric) — no shared secrets

---

## Dependency Direction

```
centerpiece-auth reads from:
  ├── TENANT_CONFIGS KV (read-only)
  └── CANONICAL_INPUTS KV (read-only, for branding)

centerpiece-auth does NOT depend on:
  ├── centerpiece-site-runtime
  ├── centerpiece-site-compositor
  └── Any other centerpiece-* repo code
```

The runtime depends on auth (via JWKS endpoint for JWT verification),
NOT the other way around.

---

## AI Behavior Rules

### MUST
- Run `PRAGMA foreign_keys = ON` on every D1 connection
- Use prepared statements for all D1 queries (prevent SQL injection)
- Use constant-time comparison for all token/hash checks
- Validate redirect URLs before processing any auth flow
- Follow the existing file structure and naming patterns

### MUST NOT
- Store plaintext secrets, tokens, or codes in D1
- Auto-create memberships with contexts other than `customer`
- Import code from `centerpiece-site-runtime` or any other runtime repo
- Hardcode tenant IDs or domains
- Skip redirect validation on any redirect-producing handler
- Import from `mjs76-dev-standards` (it is NOT part of Centerpiece)

---

## File Structure Convention

```
src/
├── worker.ts              # Entry point + router
├── types.ts               # Env interface
├── db.ts                  # D1 abstraction
├── branding.ts            # Tenant branding loader (KV) — Session 2
├── crypto/                # Cryptographic operations
│   ├── passwords.ts       # PBKDF2-SHA-256 (100k iterations) — Session 3
│   ├── jwt.ts             # Sign + verify JWT (ES256) — Session 3
│   └── refreshTokens.ts   # Generate + rotate — Session 3
├── security/
│   ├── redirectValidator.ts # Redirect URL validation — Session 3
│   ├── rateLimit.ts       # Per-IP rate limits via KV — Session 6
│   ├── headers.ts         # Security headers + CORS — Session 6
│   └── auditLog.ts        # Structured audit logging — Session 6
├── handlers/              # Route handlers
│   ├── health.ts
│   ├── jwks.ts
│   ├── register.ts        # Email/password registration
│   ├── login.ts           # Email/password login
│   ├── token.ts           # Auth code → JWT exchange
│   ├── refresh.ts         # Refresh token rotation
│   ├── logout.ts          # Single/all session revocation
│   ├── forgotPassword.ts  # Request password reset
│   ├── resetPassword.ts   # Complete password reset
│   ├── memberships.ts     # GET /api/memberships
│   ├── internalMemberships.ts  # Service-to-service membership management
│   ├── internalUsers.ts   # Service-to-service user lookup
│   └── customers.ts       # Platform customer API
├── oauth/                 # OAuth provider integrations — Session 4
│   ├── base.ts            # Shared OAuth utilities
│   ├── callback.ts        # Shared callback handler
│   ├── google.ts
│   ├── facebook.ts
│   ├── apple.ts
│   └── microsoft.ts
└── pages/                 # HTML page renderers — Session 2
    ├── renderer.ts        # Base HTML renderer
    ├── login.ts
    ├── register.ts
    └── resetPassword.ts   # Reset password page — Session 6
test/
├── helpers.ts             # Shared test utilities
├── health-and-headers.test.ts
├── pages.test.ts
├── register.test.ts
├── login.test.ts
├── token-exchange.test.ts
├── password-reset.test.ts
├── jwks.test.ts
└── redirect-validation.test.ts
```

---

## Testing

### Unit tests (`npm test`)

Test files live in `test/**/*.test.ts` and use `node:test` + `tsx`. Unit tests
mock the D1 binding or use test-helper DB stubs — they exercise handler logic,
not SQL schema correctness.

### Schema integration tests (`npm run test:integration`)

`test/integration.schema.test.ts` runs every `db.prepare(...)` SQL path against an
in-memory `better-sqlite3` database initialized with all `migrations/*.sql` files.

**Rule:** Any new raw-SQL path (`db.prepare(...)`) or new migration column/table
MUST have a corresponding integration test. Run `npm run test:integration` before
each commit that adds or changes SQL.

`npm run deploy:staging` and `npm run deploy` run `test:integration` automatically
before deploying — a failing schema test aborts the deploy.

See workspace `AI_RULES.md §SCHEMA TEST DISCIPLINE` for the full pattern.

---

## Logging Policy

Never log PII fields (email, phone, address, password, SSN, DOB, payment card data, firstName, lastName, full_name, auth tokens). Use opaque IDs (userId, tenantId) for debugging. CI greps `console.log` patterns against a PII denylist (`scripts/check-no-pii-logging.mjs`). To whitelist a deliberate case, add `// pii-allowed: <reason>` on the line immediately above the console call.
