-- Migration 0006: Fix duplicate customer memberships
--
-- SQLite treats NULLs as distinct in UNIQUE constraints, so the
-- UNIQUE(user_id, tenant_id, context, sub_role) constraint never prevented
-- duplicate customer rows (where sub_role IS NULL). Every login created
-- a new customer membership row.
--
-- This migration:
-- 1. Deletes all duplicate customer memberships, keeping only the oldest per user+tenant
-- 2. Adds a partial unique index to prevent future duplicates

-- Step 1: Delete duplicates (keep the earliest-created row per user+tenant)
DELETE FROM tenant_memberships
WHERE context = 'customer'
  AND id NOT IN (
    SELECT MIN(id) FROM tenant_memberships
    WHERE context = 'customer'
    GROUP BY user_id, tenant_id
  );

-- Step 2: Add a partial unique index for customer memberships.
-- This covers the NULL sub_role case that the table-level UNIQUE constraint misses.
CREATE UNIQUE INDEX idx_one_customer_per_tenant
  ON tenant_memberships(user_id, tenant_id)
  WHERE context = 'customer';
