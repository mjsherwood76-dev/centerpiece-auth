# centerpiece-auth — Codebase Review (2026-06-10)

Full-repo health pass per the workspace review playbook (Phases 0–4 + recommendations).
**No code changes were made** — every item below is a finding awaiting approval.
Scope: this repo only (the review session had no access to the other `centerpiece` workspace repos).

Verification notes: findings marked ✅ were independently re-verified by direct file
inspection during report consolidation; the rest were produced by targeted review passes
with grep-verified file:line references.

---

## 1. Repo Profile (Phase 0)

- **Stack:** TypeScript (`strict: true`), Cloudflare Worker, esbuild bundle, `node:test` via tsx, npm. Backend Worker with server-rendered HTML pages — no React/Vite in this repo.
- **Size:** ~22.6k LOC TypeScript — 41 source modules, 38 test files, 11 D1 migrations (0001–0012; **0011 never existed** — numbering skip, confirmed via `git log --all`).
- **Sibling dependency:** `@centerpiece/site-compositor` via `file:../centerpiece-site-compositor` — single import in `src/security/applyRateLimit.ts:27`. This **contradicts AI_RULES.md** ("does NOT depend on … centerpiece-site-compositor").
- **Test strategy is mixed:** 9 test files (`adminOauthClients`, `customers`, `internalSessions`, `stepUp`, `health-and-headers`, `internalCustomers`, `internalMemberships`, `password-reset`, `wellKnownOauth`) make **live HTTP calls to the staging worker** (`test/helpers.ts:12`); the rest mock D1 or use better-sqlite3 in-memory. `deploy` / `deploy:staging` gate on `test:integration`.

## 2. Baseline (Phase 1)

| Check | Result |
|---|---|
| `tsc --noEmit` | 1 error — missing sibling `site-compositor` checkout only (environment, not code) |
| Build | Same single failure |
| Tests | 154/161 subtests pass; all 7 failures were the review sandbox's network proxy, not code |
| Circular deps (madge) | **0** across 71 files |
| knip | 12 unused exports + 8 unused types (entry-point detection needs a knip config; "unused files" list was false-positive) |

---

## 3. Defects (Phase 2)

### Critical

| # | Location | Finding |
|---|---|---|
| C1 ✅ | `src/security/platformDomains.ts:33-34` + `src/security/redirectValidator.ts` step 6 | `CONTROLLED_SUFFIXES` includes `.workers.dev` and `.pages.dev` — public suffixes anyone can deploy under — and the redirect validator approves any hostname ending in them, in every environment. **Open redirect → auth-code theft:** attacker deploys `evil.workers.dev`, sends a victim `https://auth.centerpiecelab.com/oauth/google?redirect=https://evil.workers.dev/`; the auth code lands on the attacker origin and `handlers/token.ts` only requires the exchange origin to match the *stored* (attacker) origin; PKCE is skipped when no challenge was stored. **Fix:** remove both suffixes; allowlist exact known platform hosts per environment (e.g. `centerpiece-platform-ui-staging.pages.dev`). |
| C2 ✅ | `src/handlers/oauthToken.ts:198-262` (`handleRefreshTokenGrant`) + `src/db.ts` schema | Refresh grant never checks the presented token was issued to the authenticating client — `refresh_tokens` rows carry no `client_id`. **Any registered active third-party client can rotate any refresh token** (including first-party `cp_refresh` session tokens) into a valid access + refresh token. **Fix:** persist `client_id` + granted scopes on refresh-token rows; reject when `existing.client_id !== authenticatedClientId`. |

### High

| # | Location | Finding |
|---|---|---|
| H1 | `src/security/headers.ts:153-156` (root cause = C1) | Credentialed CORS (`Access-Control-Allow-Credentials: true`) reflected for any `*.workers.dev` / `*.pages.dev` origin. Refresh cookie is `SameSite=None`. Same fix as C1. |
| H2 | `src/oauth/microsoft.ts:258,267` + `src/oauth/callback.ts:201-223` | `emailVerified: true` is **hardcoded**, and the email may come from `preferred_username`, which Microsoft documents as unverified and attacker-settable in their own Entra tenant. Auto-linking then violates the repo's own rule. **Account takeover:** attacker sets a UPN to `victim@gmail.com` in a free Entra tenant, signs in via Microsoft, gets linked to the victim's account. **Fix:** only treat as verified on a genuine signal (`xms_edov` / `email_verified`, or consumer-tenant issuer `9188040d-…`); otherwise create a separate user. |
| H3 | `src/crypto/jwt.ts:263-264,390-392` | JWT payload encoding uses raw `btoa(JSON.stringify(...))`. `btoa` **throws** on code points > U+00FF (user named `李明` → every login 500s) and emits invalid UTF-8 for U+0080–U+00FF (`José` → malformed JWT for spec-compliant verifiers). **Fix:** `TextEncoder` → base64url on encode; mirror with `TextDecoder` on decode. |
| H4 | `src/db.ts:336-377` (`rotateRefreshToken`) + five `consume*` functions (`db.ts:253,488,530,587,641`) | All "single-use" consumption is non-atomic SELECT-then-mutate, and the rotation UPDATE has no `AND revoked_at IS NULL` guard or `meta.changes` check. Concurrent presentations of the same refresh token / auth code / reset token / verification token / OAuth state can **all succeed**, defeating single-use and theft detection. **Fix:** make the guarded write the gate (`DELETE … RETURNING` or `UPDATE … WHERE … AND revoked_at IS NULL` + `changes === 0` → treat as reuse). `db.oauthAuthorizationCodes.ts:133-144` already implements the correct pattern. |
| H5 (ops) ✅ | `package.json:18-20` | All three `db:migrate:*` scripts apply **only `0001_initial_schema.sql`**; migrations 0002–0012 are applied manually with no tracking (0012's header admits the tracking table is empty). **Fix:** adopt `wrangler d1 migrations apply` (backfill `d1_migrations`), or at minimum rename the scripts and document the manual procedure. |

### Medium

| # | Location | Finding |
|---|---|---|
| M1 | `src/oauth/callback.ts:77-79` | OAuth callback calls `ensureMembership` with **no tenant-gating check** (password registration enforces `isEmailAllowedForTenant`; OAuth skips it) and inserts membership rows even for `tenantId === '__unknown__'`. |
| M2 | `src/oauth/callback.ts:117` + `src/oauth/base.ts:201` | JWT audience comes from the client-supplied `audience` query param; any storefront flow can request `audience=admin`. Should require `isAdminDomain(redirect hostname)`. |
| M3 | `src/handlers/oauthToken.ts:255-262` | Refresh grant echoes caller-supplied `scope` with no check against granted/allowed scopes. Cosmetic today; live privilege bug once scopes are embedded in tokens. |
| M4 | `src/handlers/refresh.ts:227-239`, `internalCustomerAuth.ts:685-696`, `oauthToken.ts:236-242` | Rotation drops `device_remembered`/`device_label`/`device_fingerprint` and always re-issues at the 30-day TTL — first silent refresh silently downgrades a 90-day remembered-device session. |
| M5 | `src/crypto/jwt.ts:308,319-320` | `verifyJwt` treats a missing/non-numeric `exp` as unexpired (`undefined <= now` → false) and never checks `kid`. Defense-in-depth today; should fail closed. |
| M6 | `src/security/headers.ts:161-164` | Dev-origin check is `origin.startsWith('http://localhost')` — `http://localhost.evil.com` passes on staging (internet-facing). Parse and require exact host. |
| M7 | `src/handlers/internalMemberships.ts:127` | Full email written to the audit log — violates the repo's no-PII logging rule (other handlers deliberately log `redactEmailDomain(email)` only). |
| M8 | `src/handlers/internalMemberships.ts:149` | 409 detection matches any `'constraint'` message — FK failures (bogus userId) misreported as "Membership already exists" instead of 400. |
| M9 | `src/email/templates.ts:155-157,213` | Tenant-controlled `branding.logoUrl` and CTA `href` interpolated **unescaped** into email HTML (renderer.ts escapes the same field). Exposure limited to the deprecated SendGrid rollback path. |
| M10 | `migrations/0012` | `email_verification_tokens.token_hash` is the hot lookup column but has no index and no UNIQUE constraint — every `/verify-email` full-scans. |
| M11 | `package.json:7` + `src/security/applyRateLimit.ts:27` vs `AI_RULES.md` | Direct code dependency on sibling repo `centerpiece-site-compositor`, which AI_RULES forbids. Reconcile: vendor the limiter + policy table, or amend the rule. |
| M12 | `src/worker.ts` / `wrangler.toml` | **No cleanup cron exists** — `auth_codes`, `oauth_states`, `pkce_sessions`, `oauth_authorization_codes` accumulate expired rows forever; the four `cleanup*` helpers are dead code (see §4). Wire a `scheduled` handler + `[triggers]` cron, or delete the helpers. |
| M13 | `src/security/tenantGating.ts:32-43` | Gating lookup **fails open** (returns PUBLIC) on KV error — a KV blip ungates a domain-allowlisted tenant's registration. At least log it; consider fail-closed for allowlist tenants. |

### Low / Info

| # | Location | Finding |
|---|---|---|
| L1 | `src/oauth/facebook.ts:131-138` | `client_secret` sent in GET query string; FB accepts POST (all other providers POST). |
| L2 | `src/oauth/base.ts:200` | `code_challenge_method` cast to `'S256'` unchecked; `plain` is stored then fails opaquely at exchange. Reject at initiation. |
| L3 | `src/security/emailDomainCheck.ts:28` | `isPlatformEmailAllowed` doesn't case-normalize (its sibling at line 56 does). Fail-closed, but inconsistent. |
| L4 | `src/handlers/pkceInit.ts` | `/api/pkce/init` is an unauthenticated D1 INSERT with no entry in the rate-limit policy list. |
| L5 | `src/handlers/internalCustomers.ts:91-131` | List endpoint loads **all** matching rows then slices the page in memory. Page in SQL. |
| L6 | `src/handlers/internalCustomerAuth.ts:228`; `src/handlers/adminOauthClients.ts` (whole family) | D1 used without `PRAGMA foreign_keys = ON` (violates AI_RULES MUST). Pass the caller's `AuthDB` / route through it. |
| L7 | `src/handlers/health.ts:20` | Raw D1 exception message echoed on the public unauthenticated `/health` endpoint. |
| L8 | `src/handlers/switchTenant.ts:80` | Any `platform` sub-role (support, finance…) gets the "platform owner" bypass that scopes a JWT to any tenant — name says owner. **Verify intent.** |
| L9 | `src/handlers/forgotPassword.ts:52` | `tenantParam!` / `redirectUrl!` non-null assertions on definitely-unassigned variables in the catch path. |
| L10 | `src/handlers/register.ts:106-113` | HIBP network call runs before the `password !== confirmPassword` check (resetPassword has the right order). |
| L11 | `src/handlers/customers.ts:186-188` | LIKE search doesn't escape `%`/`_` (bound, so no injection — just wrong matches). |
| L12 | `src/email/platformApiClient.ts:67` | `...(err instanceof Error ? {} : {})` — both branches identical; the error message was meant to be surfaced. |
| L13 | `migrations/0001:17` | `idx_users_email` redundant with the `UNIQUE` constraint's implicit index. |
| L14 | `src/pages/renderer.ts:53,68` | `content.title` unescaped in `<title>` (static literals today — defense-in-depth). |
| L15 | `migrations/` | Document that `0011` was a numbering skip (one line in 0012 or a `migrations/README`). |

**Checked and clean:** account-enumeration messaging (login/forgot-password constant responses + dummy-hash timing), auto-created memberships hard-coded to `customer`, prepared statements everywhere (the one dynamic `ORDER BY` is allowlisted), internal endpoints gated by constant-time secret compare, CSP applied to every HTML response, provider ID-token handling per OIDC §3.1.3.7, zero circular dependencies.

---

## 4. Dead Code (Phase 3) — all grep-verified

- `AuthDB.getOwnerMembership` (`src/db.ts:149`) + `getOwnerMembership` (`src/db.memberships.ts:176`) — zero callers.
- Four cleanup helpers with no callers and no cron: `cleanupExpiredCodes`, `cleanupExpiredOAuthStates`, `cleanupExpiredPkceSessions` (`src/db.ts`), `cleanupExpiredAuthorizationCodes` (`src/db.oauthAuthorizationCodes.ts:154`) — see defect M12 before deleting.
- Unused imports: `sha256Hex` (`src/handlers/register.ts:24`); `ConsoleJsonLogger` instantiated-never-used (`src/handlers/internalCustomers.ts:13,17`).
- `RequestTrace.startTimer` (`src/core/requestTrace.ts:25`) — zero call sites; Server-Timing only ever emits `total`.
- Over-exported (in-module use only): `generateRandomHex` (oauth/base), `ADMIN_DOMAINS`, `SCOPE_HUMAN_TEXT`/`humanScopeText`, `oauthIcons`, `jsonError`, plus type-only exports `JwtClaims`, `JwtHeader`, `AuditEvent`, `RedirectValidationResult`, `TenantGating`, `OAuthProvider`, `OAuthAuthorizationCodeRow`, `BrandTheme`, `StyleTheme`, `OAuthThirdPartyClientRow`, `SupportedScope`.
- Obsolete one-shot scripts: `scripts/migrate-owners.mjs`, `scripts/validate-permissions-v2.mjs` (completed migrations); `scripts/reset-smoke-password.mjs:21` documents the wrong DB name; `grant-smoke-platform-admin.sql` references a nonexistent companion script.
- Legacy-not-dead (keep, documented): `email/sendgridClient.ts` + `templates.ts` behind `ALLOW_TRANSACTIONAL_SENDGRID_ROLLBACK`.
- No orphaned handlers: all 29 exported handlers are wired in `worker.ts`; no route references a missing handler.

---

## 5. Duplication Inventory (Phase 4)

### 5.1 Crypto / encoding primitives
| Duplicates | Proposed canonical |
|---|---|
| base64url encode/decode ×3 (`crypto/jwt.ts:390-423`, `crypto/signedRequest.ts:54-69`, `oauth/base.ts:246-264`) | new `src/crypto/base64url.ts` |
| "N random bytes → hex" ×4 (`refreshTokens.ts:24,55`, `oauth/base.ts:65`, `signedRequest.ts:149`) | one `generateRandomHex(bytes)` |
| hex⇄buffer helpers ×4 (`passwords.ts:119-131`, inline in `jwt.ts`, `refreshTokens.ts`, `breachedPassword.ts`) | shared hex util beside base64url |
| `constantTimeStringEqual` (`signedRequest.ts:158`) ≡ `constantTimeEqual` (`security/constantTime.ts:7`) | `security/constantTime.ts` |
| PEM private-key import (`jwt.ts:346-386`) ≡ `importApplePrivateKey` (`apple.ts:225-243`) | export from `crypto/jwt.ts` |

### 5.2 OAuth providers (4× near-identical flows)
| Duplicates | Proposed canonical |
|---|---|
| ID-token parse/validate (`google.ts:201-247`, `apple.ts:310-361`, `microsoft.ts:219-271`) | `parseIdToken(idToken, {issuerCheck, clientId, nonce})` in `oauth/base.ts` |
| Token-exchange form POST (`google.ts:147-173`, `microsoft.ts:166-192`, `apple.ts:258-283`) | `postTokenExchange(url, params)` in `oauth/base.ts` |
| Callback prologue (code/state extract → `consumeOAuthState` → provider match) ×4 | `extractAndConsumeCallback(request, env, provider)` in `oauth/base.ts` |

### 5.3 Handlers
| Duplicates | Proposed canonical |
|---|---|
| `dummyHashDelay()` ×4 (`login.ts:246`, `forgotPassword.ts:157`, `stepUp.ts:126`, `internalCustomerAuth.ts:258`) | export from `crypto/passwords.ts` |
| `resolveAudience()` ×3 (`login.ts:291`, `register.ts:298`, `refresh.ts:372`) | `security/platformDomains.ts` |
| error/success/login 302-redirect builders ×5 files | `src/util/authRedirect.ts` |
| audit IP + correlation-ID header chains ×6+ | `security/auditLog.ts` |
| `isValidEmail` ×2, `redactEmailDomain` ×2 | `emailDomainCheck.ts` / `auditLog.ts` |
| Bearer-JWT admin gates (`customers.ts:74`, `adminOauthClients.ts:54`, inline ×3) | `security/requireJwt.ts` |
| Login-success machinery (~70 lines: refresh insert → auth code → callback URL) in `login.ts:157-236` ≈ `register.ts:182-253` ≈ `refresh.ts:259-309` | shared `issueSessionAndCode(...)` |
| Rotation + theft-detection block ×3 (`refresh.ts:185-254`, `internalCustomerAuth.ts:648-699`, `oauthToken.ts:210-244`) | extend `AuthDB.rotateRefreshToken` — **same place defect H4/M4 get fixed once** |
| Hand-rolled `new Response(JSON.stringify(...))` ×10 call sites | existing `util/httpJson.ts` |
| contexts-map building loop ×5 (`token.ts`, `switchTenant.ts`) | `buildContextsMap()` in `db.memberships.ts` |
| HTML-escaper ×4 (`refresh.ts:49`, `oauthAuthorize.ts:74`, `renderer.ts:548`, `templates.ts:62`) | `src/util/escapeHtml.ts` |

### 5.4 Pages & email
| Duplicates | Proposed canonical |
|---|---|
| `buildOAuthParams` byte-identical (`pages/login.ts:195`, `pages/register.ts:153`) | `pages/renderer.ts` or shared util |
| `getErrorMessage` maps with overlapping codes ×3 pages | single map, page-specific overrides |
| Identical HTML Response + header block ×3 pages (also redundant with `addSecurityHeaders` middleware) | one `htmlResponse()` helper |
| Inline password-match `<script>` ×2 | shared snippet |
| Four ~120-line near-identical send functions (`email/send.ts:114-597`) | one `sendBrandedEmail(type, input, legacyBuilder)` — saves ~350 LOC |
| `redactEmail` ≡ `redactEmailAddress` (`send.ts:41`, `templates.ts:406`) | one copy |
| `SUPPORTED_SCOPES` vs `SCOPE_HUMAN_TEXT` parallel lists | derive one from the other + parity test |

---

## 6. Architecture & Recommendations (Phases 5–8, deferred for approval)

1. **Router:** `worker.ts` is a 494-line if-chain; `addSecurityHeaders(...)` repeated ~30×, audit-log block ~15×, audit coverage inconsistent (`/api/token`, `/api/refresh`, `/api/pkce/init`, internal sessions unaudited), success/failure classified by sniffing `Location` for `error=`. A small route table `{method, path, handler, auditEvent, rateLimitPolicy}` would halve the file and make header/audit treatment uniform. Layering itself (rate limit → dispatch → headers → catch-all 500) is sound.
2. **Tests:** make the 9 staging-coupled test files hermetic (or split them into an explicit `test:smoke` suite) so `npm test` validates local code and `deploy` doesn't gate on network state. ARCHITECTURE.md's testing section is wrong in both directions.
3. **Ops:** wire the cleanup cron (M12); fix the migration scripts (H5); add the missing `token_hash` index (M10).
4. **Tooling:** add a `knip.json` (entry: `src/worker.ts`) and keep it in CI alongside `tsc --noEmit`; no lint config exists in the repo — adding ESLint with `typescript-eslint` + a floating-promises rule would have caught several findings (recommend, not implemented).
5. **CSP:** consider nonce-based CSP to drop `'unsafe-inline'` (deliberate trade-off today, documented).

## 7. Docs Drift (Phase 9 input)

CLAUDE.md, AI_RULES.md, and ARCHITECTURE.md have drifted substantially. Highest-impact items:
- AI_RULES dependency rule contradicts the actual `site-compositor` dependency (M11).
- Access-token TTL documented as 15 min; actual `wrangler.toml` value is **1800s (30 min)** (CLAUDE.md + ARCHITECTURE.md §Token table).
- CLAUDE.md file tree lists nonexistent `security/rateLimit.ts` and omits ~half the codebase (13 of 26 handlers, `email/`, `core/`, `util/`, 7 security modules, 3 db modules); bindings list omits `RATE_LIMIT_KV` and `ANALYTICS`; vars list omits 7 actual vars.
- ARCHITECTURE.md: claims 7 D1 tables (11 exist); route map missing ~14 routes; rate-limiting section describes a replaced design; testing section inaccurate; email section says SendGrid is primary (it's the deprecated rollback — primary is `PLATFORM_API` service binding).
- AI_RULES references `scripts/check-no-pii-logging.mjs`, which doesn't exist here.
- `db:migrate:*` script docs imply full migration application (see H5).

## 8. Suggested Remediation Order

1. **C1/H1** — remove `.workers.dev`/`.pages.dev` from `CONTROLLED_SUFFIXES` (one root cause, three exposures). Small, surgical.
2. **C2 + M3** — add `client_id` (+ scopes) to refresh tokens; enforce at the refresh grant. Needs a migration.
3. **H2** — stop trusting Microsoft emails as verified.
4. **H4 + M4** — atomic guarded rotation/consumption, carrying device metadata; fixes the race and three duplicated blocks at once.
5. **H3** — UTF-8-safe JWT encoding.
6. **H5, M10, M12** — ops trio: migration scripts, token-hash index, cleanup cron.
7. Medium/low defects, then duplication consolidation (one logical area per commit), then docs rewrite.
