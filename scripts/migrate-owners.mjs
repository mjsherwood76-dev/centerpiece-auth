#!/usr/bin/env node
/**
 * Migrate Owners Script
 * =====================
 * Assigns an `owner` membership to the first seller (by created_at) on each
 * active tenant that does not already have an owner.
 *
 * Session 4 of the Tenant Ownership plan.
 *
 * CLI flags:
 *   --env staging|production   Target environment (default: staging)
 *   --execute                  Actually apply changes (default: dry-run)
 *   --overrides <file>         JSON file mapping tenantId → userId for exceptions
 *
 * Usage:
 *   node scripts/migrate-owners.mjs --env staging                  # dry-run
 *   node scripts/migrate-owners.mjs --env staging --execute        # apply
 *   node scripts/migrate-owners.mjs --env production --overrides overrides.json --execute
 *
 * Idempotent: skips tenants that already have an active owner membership.
 *
 * PowerShell:
 *   cd centerpiece-auth
 *   node scripts/migrate-owners.mjs --env staging
 */

import { execSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, writeFileSync, unlinkSync, mkdtempSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── Constants ──────────────────────────────────────────────

const TENANTS_DB_NAMES = {
  staging: 'centerpiece-tenants-db-staging',
  production: 'centerpiece-tenants-db',
};

const AUTH_DB_NAMES = {
  staging: 'centerpiece-auth-db-staging',
  production: 'centerpiece-auth-db',
};

// wrangler cwd context: TENANTS_DB is bound in centerpiece-site-runtime,
// AUTH_DB is bound in centerpiece-auth
const TENANTS_CWD_DIR = resolve(__dirname, '../../centerpiece-site-runtime');
const AUTH_CWD_DIR = resolve(__dirname, '..');

// ─── CLI Parsing ────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const flags = { env: 'staging', execute: false, overridesFile: null };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--env':
        flags.env = args[++i];
        if (!['staging', 'production'].includes(flags.env)) {
          die('--env must be "staging" or "production"');
        }
        break;
      case '--execute':
        flags.execute = true;
        break;
      case '--overrides':
        flags.overridesFile = args[++i];
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

/**
 * Execute a SELECT query against D1 via wrangler CLI and return parsed rows.
 * Uses --command + --json for machine-readable output with actual row data.
 */
function queryD1(dbName, env, sql, cwd) {
  const envFlag = env === 'production' ? '' : ` --env ${env}`;

  try {
    // --command returns actual row data with --json; --file only returns stats.
    // Escape double quotes in SQL for the shell command.
    const escapedSql = sql.replace(/"/g, '\\"');
    const cmd = `echo Y | npx wrangler d1 execute ${dbName}${envFlag} --remote --command "${escapedSql}" --json`;
    const output = execSync(cmd, {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      encoding: 'utf-8',
    });

    // wrangler --json output may have progress prefix chars before the JSON array.
    // Extract the JSON portion by finding the first '['.
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
    // Try to parse structured error from stderr
    const msg = err.stderr ? err.stderr.toString().substring(0, 500) : err.message;
    die(`D1 query failed:\nSQL: ${sql.substring(0, 200)}\nError: ${msg}`);
  }
}

/**
 * Execute a mutating SQL statement against D1 via wrangler CLI.
 */
function executeD1(dbName, env, sql, cwd, label) {
  const envFlag = env === 'production' ? '' : ` --env ${env}`;

  const tmpDir = mkdtempSync(join(tmpdir(), 'cpl-migrate-'));
  const tmpFile = join(tmpDir, 'query.sql');

  try {
    writeFileSync(tmpFile, sql, 'utf-8');

    const cmd = `echo Y | npx wrangler d1 execute ${dbName}${envFlag} --remote --file "${tmpFile}"`;
    execSync(cmd, {
      cwd,
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

/**
 * Load overrides file (tenantId → userId mapping).
 */
function loadOverrides(filePath) {
  if (!filePath) return {};
  try {
    const content = readFileSync(resolve(filePath), 'utf-8');
    const overrides = JSON.parse(content);
    if (typeof overrides !== 'object' || overrides === null || Array.isArray(overrides)) {
      die('Overrides file must be a JSON object: { "tenantId": "userId", ... }');
    }
    return overrides;
  } catch (err) {
    if (err.code === 'ENOENT') {
      die(`Overrides file not found: ${filePath}`);
    }
    die(`Failed to parse overrides file: ${err.message}`);
  }
}

// ─── Main ───────────────────────────────────────────────────

function main() {
  const flags = parseArgs();
  const overrides = loadOverrides(flags.overridesFile);
  const tenantsDbName = TENANTS_DB_NAMES[flags.env];
  const authDbName = AUTH_DB_NAMES[flags.env];

  console.log('');
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  Tenant Owner Migration');
  console.log('═══════════════════════════════════════════════════════════');
  console.log(`  Environment:  ${flags.env}`);
  console.log(`  Mode:         ${flags.execute ? 'EXECUTE' : 'DRY RUN'}`);
  console.log(`  TENANTS_DB:   ${tenantsDbName}`);
  console.log(`  AUTH_DB:      ${authDbName}`);
  console.log(`  Overrides:    ${flags.overridesFile || '(none)'}`);
  if (Object.keys(overrides).length > 0) {
    console.log(`  Override count: ${Object.keys(overrides).length}`);
  }
  console.log('═══════════════════════════════════════════════════════════');
  console.log('');

  // ── Step 1: Get all active tenants ──────────────────────

  info('Step 1: Fetching active tenants from TENANTS_DB...');
  const tenants = queryD1(
    tenantsDbName,
    flags.env,
    `SELECT id, name FROM tenants WHERE status = 'active' ORDER BY created_at ASC;`,
    TENANTS_CWD_DIR,
  );
  info(`Found ${tenants.length} active tenant(s).`);
  console.log('');

  if (tenants.length === 0) {
    info('No active tenants found. Nothing to migrate.');
    return;
  }

  // ── Step 2: For each tenant, check for existing owner and seller memberships ──

  info('Step 2: Analyzing memberships per tenant...');
  console.log('');

  const report = {
    processed: 0,
    alreadyHasOwner: 0,
    ownerAssigned: 0,
    noSellers: 0,
    multipleSellers: 0,
    overrideUsed: 0,
    failed: 0,
  };

  /** @type {Array<{tenantId: string, tenantName: string, userId: string, email: string}>} */
  const updates = [];

  /** @type {Array<{tenantId: string, tenantName: string, reason: string}>} */
  const skipped = [];

  for (const tenant of tenants) {
    report.processed++;

    // Check if tenant already has an owner
    const existingOwners = queryD1(
      authDbName,
      flags.env,
      `SELECT tm.user_id, u.email FROM tenant_memberships tm JOIN users u ON tm.user_id = u.id WHERE tm.tenant_id = '${tenant.id.replace(/'/g, "''")}' AND tm.role = 'owner' AND tm.status = 'active';`,
      AUTH_CWD_DIR,
    );

    if (existingOwners.length > 0) {
      report.alreadyHasOwner++;
      info(`  [SKIP] ${tenant.name} (${tenant.id}) — already has owner: ${existingOwners[0].email}`);
      continue;
    }

    // Get all active sellers for this tenant, ordered by created_at
    const sellers = queryD1(
      authDbName,
      flags.env,
      `SELECT tm.user_id, u.email, u.name, tm.created_at FROM tenant_memberships tm JOIN users u ON tm.user_id = u.id WHERE tm.tenant_id = '${tenant.id.replace(/'/g, "''")}' AND tm.role = 'seller' AND tm.status = 'active' ORDER BY tm.created_at ASC;`,
      AUTH_CWD_DIR,
    );

    if (sellers.length === 0) {
      report.noSellers++;
      warn(`  [NO SELLERS] ${tenant.name} (${tenant.id}) — no active sellers found. Manual owner assignment required.`);
      skipped.push({ tenantId: tenant.id, tenantName: tenant.name, reason: 'No active sellers' });
      continue;
    }

    if (sellers.length > 1) {
      report.multipleSellers++;
    }

    // Determine which user should become owner
    let chosenUser;
    const overrideUserId = overrides[tenant.id];

    if (overrideUserId) {
      // Use override if provided
      chosenUser = sellers.find(s => s.user_id === overrideUserId);
      if (!chosenUser) {
        warn(`  [OVERRIDE MISS] ${tenant.name} (${tenant.id}) — override userId ${overrideUserId} not found among active sellers. Falling back to first seller.`);
        chosenUser = sellers[0];
      } else {
        report.overrideUsed++;
        info(`  [OVERRIDE] ${tenant.name} (${tenant.id}) — using override: ${chosenUser.email}`);
      }
    } else {
      // Default: first seller by created_at
      chosenUser = sellers[0];
    }

    // Log the decision
    const multiFlag = sellers.length > 1 ? ` (${sellers.length} sellers — review recommended)` : '';
    console.log(`  [ASSIGN] ${tenant.name} (${tenant.id})`);
    console.log(`           → Owner: ${chosenUser.email} (${chosenUser.user_id})${multiFlag}`);
    if (sellers.length > 1) {
      console.log(`           All sellers:`);
      for (const s of sellers) {
        const marker = s.user_id === chosenUser.user_id ? ' ★' : '';
        console.log(`             - ${s.email} (${s.user_id}) created ${s.created_at}${marker}`);
      }
    }

    updates.push({
      tenantId: tenant.id,
      tenantName: tenant.name,
      userId: chosenUser.user_id,
      email: chosenUser.email,
    });
    report.ownerAssigned++;
  }

  // ── Step 3: Print report ────────────────────────────────

  console.log('');
  console.log('───────────────────────────────────────────────────────────');
  console.log('  Migration Report');
  console.log('───────────────────────────────────────────────────────────');
  console.log(`  Total tenants processed:    ${report.processed}`);
  console.log(`  Already have owner:         ${report.alreadyHasOwner}`);
  console.log(`  Owner to be assigned:       ${report.ownerAssigned}`);
  console.log(`  No sellers (skipped):       ${report.noSellers}`);
  console.log(`  Multiple sellers (review):  ${report.multipleSellers}`);
  console.log(`  Overrides used:             ${report.overrideUsed}`);
  console.log('───────────────────────────────────────────────────────────');
  console.log('');

  if (skipped.length > 0) {
    warn('Tenants skipped (require manual owner assignment):');
    for (const s of skipped) {
      console.log(`  - ${s.tenantName} (${s.tenantId}): ${s.reason}`);
    }
    console.log('');
  }

  if (updates.length === 0) {
    info('No updates needed. All tenants already have owners or have no sellers.');
    return;
  }

  // ── Step 4: Execute or preview ──────────────────────────

  if (!flags.execute) {
    info('[DRY RUN] The following UPDATE statements would be executed:');
    console.log('');
    for (const u of updates) {
      const sql = `UPDATE tenant_memberships SET role = 'owner' WHERE user_id = '${u.userId.replace(/'/g, "''")}' AND tenant_id = '${u.tenantId.replace(/'/g, "''")}' AND role = 'seller';`;
      console.log(`  -- ${u.tenantName}: ${u.email}`);
      console.log(`  ${sql}`);
      console.log('');
    }
    info('[DRY RUN] No changes made. Re-run with --execute to apply.');
    return;
  }

  // Execute updates
  info('Step 3: Applying owner assignments...');
  console.log('');

  let failCount = 0;
  for (const u of updates) {
    const sql = `UPDATE tenant_memberships SET role = 'owner' WHERE user_id = '${u.userId.replace(/'/g, "''")}' AND tenant_id = '${u.tenantId.replace(/'/g, "''")}' AND role = 'seller';`;
    const ok = executeD1(authDbName, flags.env, sql, AUTH_CWD_DIR, `${u.tenantName}: ${u.email} → owner`);
    if (!ok) failCount++;
  }

  if (failCount > 0) {
    report.failed = failCount;
    console.error(`\n[WARN] ${failCount} update(s) failed. Check output above.`);
  }

  // ── Step 5: Post-migration verification ─────────────────

  console.log('');
  info('Step 4: Running post-migration verification...');
  console.log('');

  // Check 1: Active tenants with no owner
  const orphanedTenants = queryD1(
    authDbName,
    flags.env,
    `SELECT DISTINCT tm.tenant_id FROM tenant_memberships tm WHERE tm.role = 'seller' AND tm.status = 'active' AND NOT EXISTS (SELECT 1 FROM tenant_memberships tm2 WHERE tm2.tenant_id = tm.tenant_id AND tm2.role = 'owner' AND tm2.status = 'active');`,
    AUTH_CWD_DIR,
  );

  if (orphanedTenants.length === 0) {
    success('Verification 1/2: All tenants with sellers now have an owner. ✓');
  } else {
    warn(`Verification 1/2: ${orphanedTenants.length} tenant(s) with sellers still have no owner:`);
    for (const t of orphanedTenants) {
      console.log(`  - ${t.tenant_id}`);
    }
  }

  // Check 2: Tenants with multiple owners
  const multiOwnerTenants = queryD1(
    authDbName,
    flags.env,
    `SELECT tenant_id, COUNT(*) as owner_count FROM tenant_memberships WHERE role = 'owner' AND status = 'active' GROUP BY tenant_id HAVING owner_count > 1;`,
    AUTH_CWD_DIR,
  );

  if (multiOwnerTenants.length === 0) {
    success('Verification 2/2: No tenants have multiple owners. ✓');
  } else {
    warn(`Verification 2/2: ${multiOwnerTenants.length} tenant(s) have multiple owners (DATA INTEGRITY ISSUE):`);
    for (const t of multiOwnerTenants) {
      console.log(`  - ${t.tenant_id}: ${t.owner_count} owners`);
    }
  }

  // ── Final Summary ─────────────────────────────────────────

  console.log('');
  console.log('═══════════════════════════════════════════════════════════');
  if (report.failed === 0) {
    success('Migration completed successfully!');
  } else {
    console.error(`[WARN] Migration completed with ${report.failed} failure(s).`);
  }
  console.log(`  Owners assigned: ${report.ownerAssigned - report.failed}`);
  console.log(`  Already had owners: ${report.alreadyHasOwner}`);
  console.log(`  Skipped (no sellers): ${report.noSellers}`);
  console.log(`  Failed: ${report.failed}`);
  console.log('═══════════════════════════════════════════════════════════');

  if (report.failed > 0) {
    process.exit(1);
  }
}

main();
