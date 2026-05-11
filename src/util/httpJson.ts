/**
 * Centralized JSON response builders for auth handlers.
 *
 * Behaviour-preserving consolidation of duplicated copies across customers,
 * impersonate, internalCustomers, internalMemberships, internalUsers,
 * memberships, switchTenant, and token handlers.
 *
 * NOTE: auth uses the flat `{ error: 'message' }` envelope — different from
 * platform-api's `{ error: { message } }`. Do not normalise.
 */
export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

export function jsonError(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}
