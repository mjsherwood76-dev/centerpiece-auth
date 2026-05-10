/**
 * Internal Cross-Tenant Customer Endpoints — Auth Worker
 *
 * GET /api/internal/customers — paginated cross-tenant customer listing
 *
 * Service-to-service endpoint gated by X-CP-Internal-Secret header.
 * Called from platform-api via Service Binding.
 *
 * @module handlers/internalCustomers
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { ConsoleJsonLogger } from '../core/logger.js';
import { constantTimeEqual } from '../security/constantTime.js';

const logger = new ConsoleJsonLogger();

// ─── Helpers ────────────────────────────────────────────────

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

function jsonError(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}

/**
 * Validate the X-CP-Internal-Secret header.
 */
function validateInternalSecret(request: Request, env: Env): Response | null {
  const internalSecret = env.INTERNAL_SECRET;
  if (!internalSecret) {
    return jsonResponse({ error: 'Internal endpoint not configured' }, 503);
  }

  const providedSecret = request.headers.get('X-CP-Internal-Secret') || '';
  if (!constantTimeEqual(providedSecret, internalSecret)) {
    return jsonResponse({ error: 'Forbidden' }, 403);
  }

  return null;
}

// ─── Types ──────────────────────────────────────────────────

interface CustomerMembershipRow {
  user_id: string;
  email: string;
  name: string;
  tenant_id: string;
  created_at: string;
}

interface CountRow {
  total: number;
}

// ─── Route Handler ──────────────────────────────────────────

/**
 * Handle GET /api/internal/customers
 *
 * Cross-tenant customer listing with search and pagination.
 *
 * Query params:
 *   ?tenantId= — filter to single tenant
 *   ?q=        — search email or name
 *   ?page=     — 1-based (default 1)
 *   ?limit=    — page size (default 25, max 100)
 */
export async function handleInternalCustomers(request: Request, env: Env): Promise<Response> {
  // Verify internal secret
  const secretError = validateInternalSecret(request, env);
  if (secretError) return secretError;

  if (request.method !== 'GET') {
    return jsonError('Method not allowed', 405);
  }

  const url = new URL(request.url);
  const tenantId = url.searchParams.get('tenantId')?.trim() || '';
  const q = url.searchParams.get('q')?.trim() || '';
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '25', 10) || 25));
  const offset = (page - 1) * limit;

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // Build WHERE clauses
  const conditions: string[] = ["tm.context = 'customer'", "tm.status = 'active'"];
  const bindings: unknown[] = [];

  if (tenantId) {
    conditions.push('tm.tenant_id = ?');
    bindings.push(tenantId);
  }

  if (q) {
    conditions.push('(u.email LIKE ? OR u.name LIKE ?)');
    bindings.push(`%${q}%`, `%${q}%`);
  }

  const whereClause = `WHERE ${conditions.join(' AND ')}`;

  // Count distinct users
  const countResult = await env.AUTH_DB
    .prepare(`SELECT COUNT(DISTINCT u.id) as total FROM users u JOIN tenant_memberships tm ON u.id = tm.user_id ${whereClause}`)
    .bind(...bindings)
    .first<CountRow>();
  const total = countResult?.total ?? 0;

  // Fetch customer memberships with user info
  // Group by user, collect tenant_ids
  const sql = `
    SELECT u.id as user_id, u.email, u.name, tm.tenant_id, u.created_at
    FROM users u
    JOIN tenant_memberships tm ON u.id = tm.user_id
    ${whereClause}
    ORDER BY u.created_at DESC
  `;
  const allRows = await env.AUTH_DB
    .prepare(sql)
    .bind(...bindings)
    .all<CustomerMembershipRow>();

  // Group by user to build customer summaries
  const userMap = new Map<string, {
    userId: string;
    email: string;
    name: string;
    tenantIds: string[];
    createdAt: string;
  }>();

  for (const row of allRows.results ?? []) {
    const existing = userMap.get(row.user_id);
    if (existing) {
      if (!existing.tenantIds.includes(row.tenant_id)) {
        existing.tenantIds.push(row.tenant_id);
      }
    } else {
      userMap.set(row.user_id, {
        userId: row.user_id,
        email: row.email,
        name: row.name || '',
        tenantIds: [row.tenant_id],
        createdAt: row.created_at,
      });
    }
  }

  // Paginate the grouped results
  const allCustomers = Array.from(userMap.values());
  const pageCustomers = allCustomers.slice(offset, offset + limit);

  const customers = pageCustomers.map((c) => ({
    userId: c.userId,
    email: c.email,
    name: c.name,
    membershipCount: c.tenantIds.length,
    tenantIds: c.tenantIds,
    createdAt: c.createdAt,
  }));

  return jsonResponse({ customers, total, page, limit });
}
