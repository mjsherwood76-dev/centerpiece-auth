/**
 * Customer Query Endpoints — Auth Worker
 *
 * GET /api/admin/customers       → Paginated, tenant-scoped customer list
 * GET /api/admin/customers/:id   → Single customer detail
 *
 * Auth: Bearer JWT with aud='admin' and roles including 'seller' or 'platform_admin'.
 * Tenant scoping: Uses JWT primaryTenantId (authoritative). Falls back to
 * X-CP-Tenant-Id header for service-binding calls where admin-api has already
 * verified the JWT and resolved the tenant.
 *
 * Phase 3.1, Session 15.
 *
 * @module handlers/customers
 */
import type { Env } from '../types.js';
import { AuthDB } from '../db.js';
import { verifyJwt, type JwtPayload } from '../crypto/jwt.js';

// ─── Types ──────────────────────────────────────────────────

interface CustomerRow {
  id: string;
  email: string;
  name: string;
  avatar_url: string | null;
  created_at: string;
  email_verified: number;
  status: string;
}

interface CustomerListResponse {
  customers: Array<{
    id: string;
    email: string;
    name: string;
    avatarUrl: string | null;
    createdAt: string;
    status: string;
  }>;
  total: number;
  page: number;
  limit: number;
}

interface CustomerDetailResponse {
  id: string;
  email: string;
  name: string;
  avatarUrl: string | null;
  createdAt: string;
  emailVerified: boolean;
  status: string;
}

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

// ─── Auth Verification ──────────────────────────────────────

interface AuthResult {
  ok: true;
  payload: JwtPayload;
  tenantId: string;
}

interface AuthFailure {
  ok: false;
  response: Response;
}

/**
 * Verify JWT and extract admin context.
 * Requires aud='admin' and roles including 'seller' or 'platform_admin'.
 */
async function verifyAdminAuth(
  request: Request,
  env: Env,
): Promise<AuthResult | AuthFailure> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { ok: false, response: jsonError('Missing or invalid Authorization header', 401) };
  }

  const token = authHeader.slice(7);
  const payload = await verifyJwt(token, env.JWT_PUBLIC_KEY);

  if (!payload) {
    return { ok: false, response: jsonError('Invalid or expired token', 401) };
  }

  // Must be an admin token
  if (payload.aud !== 'admin') {
    return { ok: false, response: jsonError('Token audience must be admin', 403) };
  }

  // Must have seller or platform_admin role
  const roles = payload.roles || [];
  const hasAdminRole = roles.includes('seller') || roles.includes('platform_admin');
  if (!hasAdminRole) {
    return { ok: false, response: jsonError('Insufficient role: requires seller or platform_admin', 403) };
  }

  // Resolve tenant ID: prefer JWT primaryTenantId, fall back to header
  const tenantId = payload.primaryTenantId
    || request.headers.get('X-CP-Tenant-Id')
    || null;

  if (!tenantId) {
    return { ok: false, response: jsonError('No tenant context available', 400) };
  }

  return { ok: true, payload, tenantId };
}

// ─── Route Dispatcher ───────────────────────────────────────

/**
 * Dispatch customer admin routes.
 *
 * @returns Response if matched, null if not a customer route.
 */
export async function handleCustomerRoutes(
  request: Request,
  env: Env,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // GET /api/admin/customers — customer list
  if (path === '/api/admin/customers' && method === 'GET') {
    return handleCustomerList(request, env);
  }

  // GET /api/admin/customers/:id — customer detail
  const detailMatch = path.match(/^\/api\/admin\/customers\/([^/]+)$/);
  if (detailMatch && method === 'GET') {
    return handleCustomerDetail(request, env, detailMatch[1]);
  }

  return null;
}

// ─── Customer List ──────────────────────────────────────────

/**
 * GET /api/admin/customers
 *
 * Query params:
 *   page   — Page number (default: 1, min: 1)
 *   limit  — Items per page (default: 20, min: 1, max: 100)
 *   search — Email or name substring (optional)
 *   sort   — Sort order (default: 'created_at_desc')
 *            Allowed: created_at_desc, created_at_asc, email_asc, email_desc, name_asc, name_desc
 */
async function handleCustomerList(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await verifyAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);

  // Parse pagination
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '20', 10) || 20));
  const offset = (page - 1) * limit;

  // Parse search
  const search = url.searchParams.get('search')?.trim() || null;

  // Parse sort
  const sortParam = url.searchParams.get('sort') || 'created_at_desc';
  const sortClause = parseSortClause(sortParam);

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  // Build query
  const baseCondition = 'tm.tenant_id = ? AND tm.role = \'customer\'';
  const params: unknown[] = [auth.tenantId];

  let searchCondition = '';
  if (search) {
    searchCondition = ' AND (u.email LIKE ? OR u.name LIKE ?)';
    const searchPattern = `%${search}%`;
    params.push(searchPattern, searchPattern);
  }

  // Count total
  const countSql = `SELECT COUNT(*) as total FROM users u JOIN tenant_memberships tm ON u.id = tm.user_id WHERE ${baseCondition}${searchCondition}`;
  const countResult = await db.raw<{ total: number }>(countSql, params);
  const total = countResult?.total ?? 0;

  // Fetch page
  const dataSql = `SELECT u.id, u.email, u.name, u.avatar_url, u.created_at, tm.status FROM users u JOIN tenant_memberships tm ON u.id = tm.user_id WHERE ${baseCondition}${searchCondition} ORDER BY ${sortClause} LIMIT ? OFFSET ?`;
  const dataParams = [...params, limit, offset];
  const rows = await db.rawAll<CustomerRow>(dataSql, dataParams);

  const response: CustomerListResponse = {
    customers: rows.map(row => ({
      id: row.id,
      email: row.email,
      name: row.name,
      avatarUrl: row.avatar_url,
      createdAt: row.created_at,
      status: row.status,
    })),
    total,
    page,
    limit,
  };

  return jsonResponse(response);
}

// ─── Customer Detail ────────────────────────────────────────

/**
 * GET /api/admin/customers/:id
 *
 * Returns single customer profile scoped to the tenant.
 * Only returns data if the user has a 'customer' membership in this tenant.
 */
async function handleCustomerDetail(
  request: Request,
  env: Env,
  customerId: string,
): Promise<Response> {
  const auth = await verifyAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const db = new AuthDB(env.AUTH_DB);
  await db.enableForeignKeys();

  const sql = `SELECT u.id, u.email, u.name, u.avatar_url, u.created_at, u.email_verified, tm.status FROM users u JOIN tenant_memberships tm ON u.id = tm.user_id WHERE u.id = ? AND tm.tenant_id = ? AND tm.role = 'customer'`;
  const row = await db.raw<CustomerRow & { email_verified: number }>(sql, [customerId, auth.tenantId]);

  if (!row) {
    return jsonError('Customer not found', 404);
  }

  const response: CustomerDetailResponse = {
    id: row.id,
    email: row.email,
    name: row.name,
    avatarUrl: row.avatar_url,
    createdAt: row.created_at,
    emailVerified: row.email_verified === 1,
    status: row.status,
  };

  return jsonResponse(response);
}

// ─── Sort Helpers ───────────────────────────────────────────

const ALLOWED_SORTS: Record<string, string> = {
  'created_at_desc': 'u.created_at DESC',
  'created_at_asc': 'u.created_at ASC',
  'email_asc': 'u.email ASC',
  'email_desc': 'u.email DESC',
  'name_asc': 'u.name ASC',
  'name_desc': 'u.name DESC',
};

function parseSortClause(sort: string): string {
  return ALLOWED_SORTS[sort] || ALLOWED_SORTS['created_at_desc'];
}
