#!/usr/bin/env node
/**
 * Validate Permissions v2 Migration
 * ==================================
 * Post-migration validation and cleanup for the Permission Model v2 migration
 * (0005_permission_model_v2.sql).
 *
 * Checks:
 *   1. Schema: context + sub_role columns exist, old role column gone
 *   2. Redundant rows: seller/manager where user is also seller/owner → remove
 *   3. Platform admin: platform/owner rows exist on __platform__
 *   4. Invariants: at most one active owner per context per tenant
 *   5. Context-sub_role validity (no invalid combinations)
 *   6. Customer rows have NULL sub_role; non-customer rows have non-NULL sub_role
 *   7. No orphaned memberships (user exists)
 *
 * CLI flags:
 *   --env staging|production   Target environment (default: staging)
 *   --apply                    Actually apply corrections (default: report only)
 *
 * Usage:
 *   cd centerpiece-auth
 *   node scripts/validate-permissions-v2.mjs --env staging            # report only
 *   node scripts/validate-permissions-v2.mjs --env staging --apply    # apply fixes
 *
 * PowerShell (from workspace root):
 *   cd centerpiece-auth; node scripts/validate-permissions-v2.mjs --env staging
 */

import { execSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync, unlinkSync, mkdtempSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── Constants ──────────────────────────────────────────────

const AUTH_DB_NAMES = {
  staging: 'centerpiece-auth-db-staging',
  production: 'centerpiece-auth-db',
};

const AUTH_CWD_DIR = resolve(__dirname, '..');

/** Valid sub-roles per context (mirrors CONTEXT_ROLES from internalMemberships.ts) */
const CONTEXT_ROLES = {
  seller: new Set(['owner', 'manager', 'designer', 'analyst', 'marketer', 'merchandiser']),
  supplier: new Set(['owner', 'manager', 'designer', 'analyst', 'marketer', 'operator']),
  platform: new Set(['owner', 'manager', 'designer', 'analyst', 'marketer', 'support', 'operations', 'finance']),
  customer: new Set(), // customer has no sub-roles (sub_role must be NULL)
};

// ─── CLI Parsing ────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const flags = { env: 'staging', apply: false };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--env':
        flags.env = args[++i];
        if (!['staging', 'production'].includes(flags.env)) {
          die('--env must be "staging" or "production"');
        }
        break;
      case '--apply':
        flags.apply = true;
        break;
      default:
        die(`Unknown flag: ${args[i]}`);
    }
  }

  return flags;
}

// ─── Helpers ────────────────────────────────────────────────

function die(msg) {
  console.error(`\n[ERROR] ${msg}`);
  process.exit(1);
}

function info(msg) {
  console.log(`[INFO]  ${msg}`);
}

function warn(msg) {
  console.log(`[WARN]  ${msg}`);
}

function success(msg) {
  console.log(`[OK]    ${msg}`);
}

function fail(msg) {
  console.log(`[FAIL]  ${msg}`);
}

/**
 * Execute a SELECT query against D1 via wrangler CLI and return parsed rows.
 */
function queryD1(dbName, env, sql) {
  try {
    // Collapse multi-line SQL to single line to avoid shell escaping issues
    const singleLine = sql.replace(/\s+/g, ' ').trim();
    const escapedSql = singleLine.replace(/"/g, '\\"');
    const cmd = `echo Y | npx wrangler d1 execute ${dbName} --remote --command "${escapedSql}" --json`;
    const output = execSync(cmd, {
      cwd: AUTH_CWD_DIR,
      stdio: ['pipe', 'pipe', 'pipe'],
      encoding: 'utf-8',
    });

    const raw = output.trim();
    const jsonStart = raw.indexOf('[');
    if (jsonStart === -1) {
      die(`D1 query returned no JSON array:\n${raw.substring(0, 500)}`);
    }
    const parsed = JSON.parse(raw.substring(jsonStart));
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed[0].results || [];
    }
    return [];
  } catch (err) {
    const msg = err.stderr ? err.stderr.toString().substring(0, 500) : err.message;
    die(`D1 query failed:\nSQL: ${sql.substring(0, 200)}\nError: ${msg}`);
  }
}

/**
 * Execute a mutating SQL statement against D1 via wrangler CLI.
 */
function executeD1(dbName, env, sql, label) {
  const tmpDir = mkdtempSync(join(tmpdir(), 'cpl-validate-'));
  const tmpFile = join(tmpDir, 'query.sql');

  try {
    writeFileSync(tmpFile, sql, 'utf-8');

    const cmd = `echo Y | npx wrangler d1 execute ${dbName} --remote --file "${tmpFile}" -y`;
    execSync(cmd, {
      cwd: AUTH_CWD_DIR,
      stdio: 'pipe',
      encoding: 'utf-8',
    });
    success(`${label}: OK`);
    return true;
  } catch (err) {
    const msg = err.stderr ? err.stderr.toString().substring(0, 500) : err.message;
    console.error(`[FAIL] ${label}: ${msg}`);
    return false;
  } finally {
    try { unlinkSync(tmpFile); } catch { /* ignore */ }
    try { rmdirSync(tmpDir); } catch { /* ignore */ }
  }
}

// ─── Validation Checks ─────────────────────────────────────

/**
 * Check 1: Verify schema has context + sub_role columns and no role column.
 */
function checkSchema(dbName, env) {
  info('Check 1: Verifying schema...');
  const columns = queryD1(dbName, env, `PRAGMA table_info(tenant_memberships);`);

  const columnNames = columns.map(c => c.name);
  const hasContext = columnNames.includes('context');
  const hasSubRole = columnNames.includes('sub_role');
  const hasOldRole = columnNames.includes('role');

  if (hasContext && hasSubRole && !hasOldRole) {
    success('Schema correct: context + sub_role present, old role column removed.');
    return true;
  }

  if (hasOldRole) {
    fail('Old "role" column still exists! Migration may not have run.');
  }
  if (!hasContext) {
    fail('"context" column missing!');
  }
  if (!hasSubRole) {
    fail('"sub_role" column missing!');
  }
  return false;
}

/**
 * Check 2: Find and remove redundant seller/manager rows where user is also seller/owner.
 * When a user had both 'seller' and 'owner' roles, the migration creates:
 *   - seller/manager (from old 'seller' role)
 *   - seller/owner   (from old 'owner' role)
 * The seller/manager row is redundant since owner implies full access.
 */
function checkRedundantManagerRows(dbName, env, apply) {
  info('Check 2: Looking for redundant seller/manager rows (user is also seller/owner)...');

  const redundant = queryD1(dbName, env,
    `SELECT mgr.id, mgr.user_id, mgr.tenant_id, u.email
     FROM tenant_memberships mgr
     JOIN users u ON mgr.user_id = u.id
     WHERE mgr.context = 'seller' AND mgr.sub_role = 'manager'
       AND EXISTS (
         SELECT 1 FROM tenant_memberships own
         WHERE own.user_id = mgr.user_id
           AND own.tenant_id = mgr.tenant_id
           AND own.context = 'seller'
           AND own.sub_role = 'owner'
       );`
  );

  if (redundant.length === 0) {
    success('No redundant seller/manager rows found.');
    return { found: 0, fixed: 0 };
  }

  warn(`Found ${redundant.length} redundant seller/manager row(s) to remove:`);
  for (const r of redundant) {
    console.log(`  - ${r.email} on tenant ${r.tenant_id} (membership ${r.id})`);
  }

  if (!apply) {
    info('[REPORT] Re-run with --apply to remove these rows.');
    return { found: redundant.length, fixed: 0 };
  }

  let fixed = 0;
  for (const r of redundant) {
    const sql = `DELETE FROM tenant_memberships WHERE id = '${r.id.replace(/'/g, "''")}';`;
    const ok = executeD1(dbName, env, sql, `Remove redundant manager: ${r.email} / ${r.tenant_id}`);
    if (ok) fixed++;
  }

  return { found: redundant.length, fixed };
}

/**
 * Check 3: Verify platform_admin users were migrated to platform/owner on __platform__.
 */
function checkPlatformOwners(dbName, env) {
  info('Check 3: Verifying platform/owner memberships on __platform__...');

  const platformOwners = queryD1(dbName, env,
    `SELECT tm.user_id, u.email
     FROM tenant_memberships tm
     JOIN users u ON tm.user_id = u.id
     WHERE tm.context = 'platform' AND tm.sub_role = 'owner' AND tm.status = 'active';`
  );

  if (platformOwners.length === 0) {
    warn('No platform/owner memberships found. If there were platform_admin users, migration may have failed.');
    return false;
  }

  success(`Found ${platformOwners.length} platform/owner membership(s):`);
  for (const p of platformOwners) {
    console.log(`  - ${p.email} (${p.user_id})`);
  }

  // Verify they're on __platform__ tenant
  const wrongTenant = queryD1(dbName, env,
    `SELECT tm.user_id, tm.tenant_id, u.email
     FROM tenant_memberships tm
     JOIN users u ON tm.user_id = u.id
     WHERE tm.context = 'platform' AND tm.tenant_id != '__platform__';`
  );

  if (wrongTenant.length > 0) {
    fail(`Found ${wrongTenant.length} platform membership(s) NOT on __platform__:`);
    for (const w of wrongTenant) {
      console.log(`  - ${w.email} on tenant ${w.tenant_id}`);
    }
    return false;
  }

  success('All platform memberships are on __platform__.');
  return true;
}

/**
 * Check 4: Verify at most one active owner per context per tenant.
 */
function checkOwnerUniqueness(dbName, env) {
  info('Check 4: Checking owner uniqueness (at most one active owner per context per tenant)...');

  const duplicateOwners = queryD1(dbName, env,
    `SELECT tenant_id, context, COUNT(*) as owner_count
     FROM tenant_memberships
     WHERE sub_role = 'owner' AND status = 'active'
     GROUP BY tenant_id, context
     HAVING COUNT(*) > 1;`
  );

  if (duplicateOwners.length === 0) {
    success('Owner uniqueness holds: at most one active owner per context per tenant.');
    return true;
  }

  fail(`Found ${duplicateOwners.length} context(s) with multiple active owners:`);
  for (const d of duplicateOwners) {
    console.log(`  - tenant ${d.tenant_id}, context ${d.context}: ${d.owner_count} owners`);
  }
  return false;
}

/**
 * Check 5: Verify all context + sub_role combinations are valid.
 */
function checkContextSubRoleValidity(dbName, env) {
  info('Check 5: Checking context + sub_role validity...');

  const allRows = queryD1(dbName, env,
    `SELECT id, user_id, tenant_id, context, sub_role, status FROM tenant_memberships;`
  );

  const invalid = [];
  for (const row of allRows) {
    const validRoles = CONTEXT_ROLES[row.context];
    if (!validRoles) {
      invalid.push({ ...row, reason: `Unknown context: ${row.context}` });
      continue;
    }

    if (row.context === 'customer') {
      if (row.sub_role !== null) {
        invalid.push({ ...row, reason: `Customer must have NULL sub_role, got: ${row.sub_role}` });
      }
    } else {
      if (row.sub_role === null) {
        invalid.push({ ...row, reason: `Non-customer context ${row.context} must have a sub_role` });
      } else if (!validRoles.has(row.sub_role)) {
        invalid.push({ ...row, reason: `sub_role '${row.sub_role}' not valid for context '${row.context}'` });
      }
    }
  }

  if (invalid.length === 0) {
    success(`All ${allRows.length} membership(s) have valid context + sub_role combinations.`);
    return true;
  }

  fail(`Found ${invalid.length} invalid membership(s):`);
  for (const inv of invalid) {
    console.log(`  - id=${inv.id} user=${inv.user_id} tenant=${inv.tenant_id} context=${inv.context} sub_role=${inv.sub_role}`);
    console.log(`    Reason: ${inv.reason}`);
  }
  return false;
}

/**
 * Check 6: Verify no orphaned memberships (user must exist).
 */
function checkOrphanedMemberships(dbName, env) {
  info('Check 6: Checking for orphaned memberships (user missing)...');

  const orphaned = queryD1(dbName, env,
    `SELECT tm.id, tm.user_id, tm.tenant_id, tm.context, tm.sub_role
     FROM tenant_memberships tm
     LEFT JOIN users u ON tm.user_id = u.id
     WHERE u.id IS NULL;`
  );

  if (orphaned.length === 0) {
    success('No orphaned memberships found.');
    return true;
  }

  fail(`Found ${orphaned.length} orphaned membership(s) (user does not exist):`);
  for (const o of orphaned) {
    console.log(`  - id=${o.id} user=${o.user_id} tenant=${o.tenant_id} context=${o.context} sub_role=${o.sub_role}`);
  }
  return false;
}

/**
 * Check 7: Summary — row counts by context + sub_role.
 */
function printSummary(dbName, env) {
  info('Summary: Membership counts by context + sub_role...');

  const counts = queryD1(dbName, env,
    `SELECT context, sub_role, COUNT(*) as count
     FROM tenant_memberships
     GROUP BY context, sub_role
     ORDER BY context, sub_role;`
  );

  console.log('');
  console.log('  ┌──────────────┬───────────────┬───────┐');
  console.log('  │ Context      │ Sub-Role      │ Count │');
  console.log('  ├──────────────┼───────────────┼───────┤');
  for (const row of counts) {
    const ctx = (row.context || '').padEnd(12);
    const sr = (row.sub_role || '(null)').padEnd(13);
    const cnt = String(row.count).padStart(5);
    console.log(`  │ ${ctx} │ ${sr} │ ${cnt} │`);
  }
  console.log('  └──────────────┴───────────────┴───────┘');
  console.log('');

  const total = counts.reduce((sum, r) => sum + r.count, 0);
  info(`Total memberships: ${total}`);
}

// ─── Main ───────────────────────────────────────────────────

function main() {
  const flags = parseArgs();
  const dbName = AUTH_DB_NAMES[flags.env];

  console.log('');
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  Permission Model v2 — Post-Migration Validation');
  console.log('═══════════════════════════════════════════════════════════');
  console.log(`  Environment:  ${flags.env}`);
  console.log(`  Mode:         ${flags.apply ? 'APPLY' : 'REPORT ONLY'}`);
  console.log(`  AUTH_DB:      ${dbName}`);
  console.log('═══════════════════════════════════════════════════════════');
  console.log('');

  const results = {
    schemaOk: false,
    redundant: { found: 0, fixed: 0 },
    platformOk: false,
    ownerUniqueOk: false,
    validityOk: false,
    orphanedOk: false,
  };

  // ── Check 1: Schema ─────────────────────────────────────
  results.schemaOk = checkSchema(dbName, flags.env);
  console.log('');
  if (!results.schemaOk) {
    die('Schema check failed. Migration may not have run. Aborting remaining checks.');
  }

  // ── Check 2: Redundant manager rows ─────────────────────
  results.redundant = checkRedundantManagerRows(dbName, flags.env, flags.apply);
  console.log('');

  // ── Check 3: Platform owners ────────────────────────────
  results.platformOk = checkPlatformOwners(dbName, flags.env);
  console.log('');

  // ── Check 4: Owner uniqueness ───────────────────────────
  results.ownerUniqueOk = checkOwnerUniqueness(dbName, flags.env);
  console.log('');

  // ── Check 5: Context + sub_role validity ────────────────
  results.validityOk = checkContextSubRoleValidity(dbName, flags.env);
  console.log('');

  // ── Check 6: Orphaned memberships ───────────────────────
  results.orphanedOk = checkOrphanedMemberships(dbName, flags.env);
  console.log('');

  // ── Summary ─────────────────────────────────────────────
  printSummary(dbName, flags.env);

  // ── Final Report ────────────────────────────────────────
  console.log('───────────────────────────────────────────────────────────');
  console.log('  Validation Report');
  console.log('───────────────────────────────────────────────────────────');
  console.log(`  Schema correct:           ${results.schemaOk ? 'PASS' : 'FAIL'}`);
  console.log(`  Redundant managers:       ${results.redundant.found} found, ${results.redundant.fixed} fixed`);
  console.log(`  Platform owners valid:    ${results.platformOk ? 'PASS' : 'FAIL/WARN'}`);
  console.log(`  Owner uniqueness:         ${results.ownerUniqueOk ? 'PASS' : 'FAIL'}`);
  console.log(`  Context+sub_role valid:   ${results.validityOk ? 'PASS' : 'FAIL'}`);
  console.log(`  No orphaned memberships:  ${results.orphanedOk ? 'PASS' : 'FAIL'}`);
  console.log('───────────────────────────────────────────────────────────');
  console.log('');

  const allPassed = results.schemaOk
    && results.redundant.found === 0
    && results.platformOk
    && results.ownerUniqueOk
    && results.validityOk
    && results.orphanedOk;

  const passedAfterFix = results.schemaOk
    && results.redundant.found === results.redundant.fixed
    && results.platformOk
    && results.ownerUniqueOk
    && results.validityOk
    && results.orphanedOk;

  if (allPassed) {
    success('All checks passed. Data is ready for Session 2.');
  } else if (passedAfterFix) {
    success('All checks passed after applying fixes. Run again in report mode to confirm.');
  } else if (results.redundant.found > 0 && !flags.apply) {
    warn('Redundant rows found. Re-run with --apply to fix, then re-validate.');
  } else {
    fail('Some checks failed. Review output above and fix manually before proceeding to Session 2.');
    process.exit(1);
  }
}

main();
