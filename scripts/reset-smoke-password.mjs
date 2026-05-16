#!/usr/bin/env node
/**
 * Reset Smoke User Password
 * =========================
 * Generates a SQL UPDATE statement that sets a new password hash for a given
 * user in the auth `users` table, using the exact same PBKDF2-SHA-256 format
 * as `centerpiece-auth/src/crypto/passwords.ts`:
 *
 *   format: pbkdf2:100000:salt_hex:hash_hex
 *
 * Use this when the smoke-test user's password is lost AND the email-driven
 * forgot-password flow is unavailable (Path B of Fix_Enable_E2E_Smoke_Testing).
 *
 * The script does NOT touch any database itself. It emits SQL to stdout that
 * the operator pipes into `wrangler d1 execute`.
 *
 * Usage:
 *   cd centerpiece-auth
 *   node scripts/reset-smoke-password.mjs <email> <new-password> > reset.sql
 *   npx wrangler d1 execute centerpiece-auth-staging --remote --file reset.sql
 *   rm reset.sql   # contains the hash — don't leave it on disk
 *
 * The new password should NOT be committed anywhere; store it in 1Password /
 * the team vault and copy it into centerpiece-site-tester/.env after the
 * UPDATE succeeds.
 */
import { argv, exit } from 'node:process';

const ITERATIONS = 100_000;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;

async function hashPassword(password) {
  const salt = new Uint8Array(SALT_LENGTH);
  crypto.getRandomValues(salt);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    KEY_LENGTH * 8,
  );

  return `pbkdf2:${ITERATIONS}:${toHex(salt)}:${toHex(new Uint8Array(derivedBits))}`;
}

function toHex(buf) {
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

function sqlEscape(value) {
  return value.replace(/'/g, "''");
}

async function main() {
  const email = argv[2];
  const password = argv[3];

  if (!email || !password) {
    console.error('Usage: node scripts/reset-smoke-password.mjs <email> <new-password>');
    console.error('');
    console.error('Emits an UPDATE statement to stdout. Pipe to a .sql file and apply via wrangler.');
    exit(1);
  }

  if (password.length < 12) {
    console.error('Refusing to hash a password shorter than 12 characters.');
    exit(1);
  }

  const hash = await hashPassword(password);
  const normalisedEmail = email.trim().toLowerCase();

  process.stdout.write(
    `UPDATE users SET password_hash = '${sqlEscape(hash)}', updated_at = unixepoch() WHERE email = '${sqlEscape(normalisedEmail)}';\n`,
  );
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack : err);
  exit(1);
});
