/**
 * Parse a request body that may be either `application/json` or
 * `application/x-www-form-urlencoded` (the OAuth2/login flow accepts both).
 *
 * Behaviour-preserving consolidation of duplicated try/catch blocks in
 * login, register, forgotPassword, and resetPassword handlers — all of which
 * flatten to a `Record<string, string>` keyed by form field name.
 *
 * The helper itself does NOT throw — but `request.json()` and
 * `request.formData()` may throw if the body is malformed. Callers must wrap
 * the call in a try/catch matching their existing error path (each handler
 * has a different fallback redirect on parse failure, so error handling
 * stays at the call site).
 *
 * NOTE: token.ts is intentionally NOT consolidated here — it only accepts
 * JSON and parses additional metadata that is best left inline.
 */
export async function parseRequestBody(request: Request): Promise<Record<string, string>> {
  const contentType = request.headers.get('Content-Type') || '';

  if (contentType.includes('application/json')) {
    return (await request.json()) as Record<string, string>;
  }

  const formData = await request.formData();
  const body: Record<string, string> = {};
  formData.forEach((value, key) => {
    if (typeof value === 'string') body[key] = value;
  });
  return body;
}
