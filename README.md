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
