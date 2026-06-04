/**
 * Tenant Access-Gating Lookup (Phase 3.25 Tenant Access Gating)
 *
 * Reads the access-gating fields a tenant config carries (declared by the
 * compositor in Session 1) from the read-only TENANT_CONFIGS KV namespace.
 * Auth and the compositor are NOT code peers — auth reads the resolved config
 * as DATA from KV rather than importing `@centerpiece/site-compositor`.
 *
 * A tenant is "gated" when its `defaultAccessRequirement.policy` is non-`public`
 * (today: `authenticated` or `domain-allowlist`). The `allowedEmailDomains` list
 * is the lowercased bare-domain allowlist used by `domain-allowlist` enforcement
 * (Session 3) and to decide whether to send a verification email on register.
 */
import type { Env } from '../types.js';

export interface TenantGating {
  /** True when the tenant default requirement is non-`public`. */
  gated: boolean;
  /** Effective default policy; `public` when unset. */
  policy: 'public' | 'authenticated' | 'domain-allowlist';
  /** Lowercased bare domains; empty when unset. */
  allowedEmailDomains: string[];
}

const PUBLIC: TenantGating = { gated: false, policy: 'public', allowedEmailDomains: [] };

/**
 * Load the gating posture for a tenant. Never throws — on any KV/parse error or
 * missing tenant it returns the public (ungated) default, leaving the
 * not-gated code path unchanged for the public-first platform.
 */
export async function loadTenantGating(env: Env, tenantId: string | null): Promise<TenantGating> {
  if (!tenantId) return PUBLIC;

  let config: Record<string, unknown> | null;
  try {
    const record = await env.TENANT_CONFIGS.get(`tenant:${tenantId}`, 'json') as Record<string, unknown> | null;
    // D1→KV sync stores a TenantConfigRecord wrapper; extract the inner config.
    config = (record?.config ?? record) as Record<string, unknown> | null;
  } catch {
    return PUBLIC;
  }
  if (!config) return PUBLIC;

  const requirement = config.defaultAccessRequirement as { policy?: unknown } | undefined;
  const rawPolicy = typeof requirement?.policy === 'string' ? requirement.policy : 'public';
  const policy: TenantGating['policy'] =
    rawPolicy === 'authenticated' || rawPolicy === 'domain-allowlist' ? rawPolicy : 'public';

  const rawDomains = config.allowedEmailDomains;
  const allowedEmailDomains = Array.isArray(rawDomains)
    ? rawDomains.filter((d): d is string => typeof d === 'string').map(d => d.trim().toLowerCase()).filter(Boolean)
    : [];

  return {
    gated: policy !== 'public',
    policy,
    allowedEmailDomains,
  };
}
