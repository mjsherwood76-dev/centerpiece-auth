/**
 * Token Exchange Handler
 *
 * POST /api/token — Exchange authorization code for JWT access token
 *
 * Supports two callers:
 *
 * 1. **Server-to-server** (runtime Worker → auth Worker):
 *    Body: `{ code, tenant_id, redirect_origin, code_verifier? }`
 *
 * 2. **Admin SPA** (browser → auth Worker, with PKCE):
 *    Body: `{ grant_type: "authorization_code", code, redirect_uri, code_verifier }`
 *    - `tenant_id` and `redirect_origin` are derived from the stored auth code row
 *
 * Flow:
 * 1. Accept and normalize input fields
 * 2. Hash the code, look up in `auth_codes` table
 * 3. Verify: not expired, redirect_origin matches
 * 4. If auth code has `code_challenge`: verify PKCE (SHA256(code_verifier) === code_challenge)
 * 5. Delete row immediately (single-use enforcement)
 * 6. Look up user details
 * 7. For admin audience: query tenant_memberships for contexts + primaryTenantId
 * 8. Return signed JWT access token
 *
 * Security:
 * - Code stored as SHA-256 hash — plaintext never in DB
 * - Single-use: deleted on consumption
 * - redirect_origin must match (prevents code interception)
 * - tenant_id verified from DB row (admin SPA) or from caller (runtime)
 * - PKCE enforced for admin flows (code_challenge stored with auth code)
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import {
  signJwt,
  sha256Hex,
  sha256Base64Url,
  buildCustomerJwtPayload,
  buildAdminJwtPayload,
  type UnsignedJwtClaims,
} from '../crypto/jwt.js';

/**
 * Handle POST /api/token
 *
 * Accepts JSON body:
 *   Runtime:  { code, tenant_id, redirect_origin, code_verifier? }
 *   Admin:    { grant_type: "authorization_code", code, redirect_uri, code_verifier }
 *
 * Returns JSON: { access_token, token_type, expires_in }
 */
export async function handleTokenExchange(request: Request, env: Env): Promise<Response> {
  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // ── Parse JSON body ──
  let code: string;
  let tenantId: string;
  let redirectOrigin: string;
  let codeVerifier: string | undefined;
  let requestedTenantId: string | undefined; // Optional tenant hint for admin SPA re-auth

  try {
    const body = await request.json() as Record<string, string>;
    code = (body.code || '').trim();
    codeVerifier = body.code_verifier ? body.code_verifier.trim() : undefined;
    requestedTenantId = body.tenantId ? body.tenantId.trim() : undefined;

    // Support two field naming conventions:
    // 1. Runtime (server-to-server): tenant_id + redirect_origin
    // 2. Admin SPA (browser): redirect_uri (tenant_id derived from auth code row)
    tenantId = (body.tenant_id || '').trim();
    if (body.redirect_origin) {
      redirectOrigin = body.redirect_origin.trim();
    } else if (body.redirect_uri) {
      // Admin SPA sends redirect_uri — extract origin from it
      try {
        redirectOrigin = new URL(body.redirect_uri.trim()).origin;
      } catch {
        return jsonError('Invalid redirect_uri', 400);
      }
    } else {
      redirectOrigin = '';
    }
  } catch {
    return jsonError('Invalid request body', 400);
  }

  if (!code || !redirectOrigin) {
    return jsonError('Missing required fields: code, redirect_origin (or redirect_uri)', 400);
  }

  // ── Hash the code and look up ──
  const codeHash = await sha256Hex(code);
  const authCodeRow = await db.consumeAuthCode(codeHash);

  if (!authCodeRow) {
    return jsonError('Invalid or expired authorization code', 400);
  }

  // ── Verify expiration ──
  const now = Math.floor(Date.now() / 1000);
  if (authCodeRow.expires_at <= now) {
    return jsonError('Authorization code has expired', 400);
  }

  // ── Verify tenant_id if provided (runtime flow), else use from auth code row ──
  if (tenantId) {
    if (authCodeRow.tenant_id !== tenantId) {
      console.error(
        `Token exchange tenant mismatch: expected=${authCodeRow.tenant_id}, got=${tenantId}`
      );
      return jsonError('Authorization code tenant mismatch', 400);
    }
  } else {
    // Admin SPA flow — tenant_id comes from the auth code row
    tenantId = authCodeRow.tenant_id;
  }

  // ── Verify redirect_origin matches ──
  if (authCodeRow.redirect_origin !== redirectOrigin) {
    console.error(
      `Token exchange origin mismatch: expected=${authCodeRow.redirect_origin}, got=${redirectOrigin}`
    );
    return jsonError('Authorization code origin mismatch', 400);
  }

  // ── PKCE verification (required when code_challenge is present) ──
  if (authCodeRow.code_challenge) {
    if (!codeVerifier) {
      return jsonError('PKCE code_verifier is required for this authorization code', 400);
    }
    // S256: BASE64URL(SHA256(code_verifier)) === code_challenge
    const verifierHash = await sha256Base64Url(codeVerifier);
    if (verifierHash !== authCodeRow.code_challenge) {
      return jsonError('PKCE code_verifier does not match code_challenge', 400);
    }
  }

  // ── Look up user ──
  const user = await db.getUserById(authCodeRow.user_id);
  if (!user) {
    console.error(`Token exchange: user not found: ${authCodeRow.user_id}`);
    return jsonError('User not found', 400);
  }

  // ── Sign JWT ──
  const ttlSeconds = parseInt(env.ACCESS_TOKEN_TTL_SECONDS || '900', 10);

  // Admin enrichment lives outside the if-block so the response logic
  // (tenantIdFallback) can read primaryTenantId after the factory call.
  let adminContexts: Record<string, string[]> = {};
  let adminPrimaryTenantId: string | null = null;

  // ── Admin token enrichment: compute contexts + primaryTenantId ──
  if (authCodeRow.aud === 'admin') {
    let memberships = await db.getAdminMemberships(user.id);

    // ── Defense-in-Depth Layer 2: strip platform context for non-@centerpiecelab.com emails ──
    if (!user.email.endsWith('@centerpiecelab.com')) {
      const before = memberships.length;
      memberships = memberships.filter(m => m.context !== 'platform');
      if (memberships.length !== before) {
        console.warn('Token issuance: stripped platform context for non-centerpiecelab email', {
          userId: user.id,
          email: user.email,
        });
      }
    }

    // Check for platform owner on __platform__ tenant (super admin)
    const isPlatformOwner = memberships.some(
      m => m.tenant_id === '__platform__' && m.context === 'platform' && m.sub_role === 'owner'
    );

    if (isPlatformOwner) {
      // Super admin: gets platform context, can switch tenants via API.
      // Build platform contexts from __platform__ memberships
      const platformMemberships = memberships.filter(m => m.tenant_id === '__platform__' && m.context === 'platform');
      for (const m of platformMemberships) {
        if (!adminContexts['platform']) adminContexts['platform'] = [];
        if (m.sub_role && !adminContexts['platform'].includes(m.sub_role)) {
          adminContexts['platform'].push(m.sub_role);
        }
      }

      // Default primaryTenantId to first real tenant (not __platform__)
      // so the admin SPA can load tenant config without a tenant selector.
      // Prefer seller-owner membership when choosing primary tenant.
      const realTenants = memberships.filter(
        m => m.tenant_id !== '__platform__' && m.tenant_id !== '__unknown__'
      );
      const realTenant = realTenants.find(m => m.context === 'seller' && m.sub_role === 'owner') ?? realTenants[0];
      adminPrimaryTenantId = realTenant?.tenant_id ?? null;

      // Also include contexts from the primary tenant if one exists
      if (adminPrimaryTenantId) {
        const tenantMemberships = memberships.filter(m => m.tenant_id === adminPrimaryTenantId);
        for (const m of tenantMemberships) {
          if (!adminContexts[m.context]) adminContexts[m.context] = [];
          if (m.sub_role && !adminContexts[m.context].includes(m.sub_role)) {
            adminContexts[m.context].push(m.sub_role);
          }
        }
      }
    } else {
      // Prefer tenant where user has seller-owner, then any seller context, then any
      const ownerMembership = memberships.find(m => m.context === 'seller' && m.sub_role === 'owner');
      const sellerMembership = memberships.find(m => m.context === 'seller');
      adminPrimaryTenantId = ownerMembership?.tenant_id ?? sellerMembership?.tenant_id ?? memberships[0]?.tenant_id ?? null;

      // Build contexts map from memberships on the primary tenant only
      const primaryMemberships = memberships.filter(m => m.tenant_id === adminPrimaryTenantId);
      for (const m of primaryMemberships) {
        if (!adminContexts[m.context]) adminContexts[m.context] = [];
        if (m.sub_role && !adminContexts[m.context].includes(m.sub_role)) {
          adminContexts[m.context].push(m.sub_role);
        }
      }
    }

    // ── Optional tenantId override (admin SPA re-auth with stored selection) ──
    if (requestedTenantId && requestedTenantId !== adminPrimaryTenantId) {
      // Verify membership on requested tenant
      const hasAccess = isPlatformOwner || memberships.some(
        m => m.tenant_id === requestedTenantId && m.context !== 'customer',
      );

      if (hasAccess) {
        // Override primaryTenantId and rebuild contexts for the requested tenant
        adminPrimaryTenantId = requestedTenantId;

        // Clear and rebuild contexts
        for (const key of Object.keys(adminContexts)) {
          if (key !== 'platform') delete adminContexts[key];
        }
        const tenantMemberships = memberships.filter(m => m.tenant_id === requestedTenantId);
        for (const m of tenantMemberships) {
          if (!adminContexts[m.context]) adminContexts[m.context] = [];
          if (m.sub_role && !adminContexts[m.context].includes(m.sub_role)) {
            adminContexts[m.context].push(m.sub_role);
          }
        }
      } else {
        console.warn(`Token exchange: tenantId hint '${requestedTenantId}' ignored — no membership for user ${user.id}`);
      }
    }
  }

  // Track tenantIdFallback for response (must be declared outside admin block scope)
  const responseTenantIdFallback = (authCodeRow.aud === 'admin' && requestedTenantId)
    ? adminPrimaryTenantId !== requestedTenantId
    : false;

  // Build the unsigned payload via the right factory.
  const unsignedPayload: UnsignedJwtClaims = authCodeRow.aud === 'admin'
    ? buildAdminJwtPayload({
        userId: user.id,
        email: user.email,
        name: user.name || '',
        iss: env.AUTH_DOMAIN,
        contexts: adminContexts,
        primaryTenantId: adminPrimaryTenantId,
      })
    : buildCustomerJwtPayload({
        userId: user.id,
        email: user.email,
        name: user.name || '',
        iss: env.AUTH_DOMAIN,
      });

  const accessToken = await signJwt(
    unsignedPayload,
    env.JWT_PRIVATE_KEY,
    ttlSeconds
  );

  // ── Return token ──
  const responseBody: Record<string, unknown> = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ttlSeconds,
  };
  if (responseTenantIdFallback) {
    responseBody.tenantIdFallback = true;
  }

  return new Response(
    JSON.stringify(responseBody),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    }
  );
}

// ─── Helpers ────────────────────────────────────────────────

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

