# ⚠ MERGED INTO THE CENTERPIECE MONOREPO

Consolidated into mjsherwood76-dev/centerpiece at /centerpiece-auth/ on 2026-06-11
(ADR 023). Full history preserved there (git log -- centerpiece-auth/). This remote is
archived read-only; final pre-merge state is tagged pre-monorepo-final.

DO NOT push here.

---

# centerpiece-auth

Centralized identity provider for the Centerpiece platform.

Cloudflare Worker handling authentication, JWT issuance, and tenant-scoped authorization.
Production: `auth.centerpiecelab.com`. Staging: `centerpiece-auth-staging.mjsherwood76.workers.dev`.

## Quick Start

```bash
npm install
npm run build
npm run deploy:staging
```

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for full details.

## AI Rules

See [AI_RULES.md](./AI_RULES.md) for AI agent constraints.
