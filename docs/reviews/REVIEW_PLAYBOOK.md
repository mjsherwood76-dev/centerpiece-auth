# Codebase Review, Cleanup & Consolidation Prompt
### For TypeScript / React / Node.js / Vite projects (centerpiece workspace)

## Objective

Perform a full-codebase health pass: review code for correctness, remove dead code, consolidate duplication introduced through iterative AI-assisted development, refactor toward a cleaner DRY architecture **without changing runtime behavior**, and recommend improvements to performance, cost, best practices, and documentation.

This is a multi-phase engagement. Complete each phase, report findings, and wait for approval before making the changes proposed in that phase (unless instructed to proceed autonomously).

---

## Ground Rules (apply to every phase)

1. **Do NOT change runtime behavior.** This is review and refactoring, not feature work. If a genuine bug is found, report it separately (Phase 2) — do not silently "fix" behavior during a refactor.
2. **Preserve all existing tests.** Update imports and paths, never delete coverage.
3. **One logical change per commit.** Each commit should be independently reviewable and revertible, with a message describing what was consolidated/removed and why.
4. **Verify after every group of changes:** type-check, lint, build, and test (commands discovered in Phase 0).
5. **When uncertain, document instead of changing.** If two pieces of code look similar but may serve different domains or edge cases, write up the difference rather than forcibly merging.
6. **No new dependencies** without explicit approval. Prefer removing dependencies over adding them.

---

## Phase 0: Repository Discovery (do this first, before any analysis)

Inspect the repository and record the ground truth. All later phases must use what is found here — never assume Angular-style or template-project conventions.

1. **Workspace shape.** Determine whether this is a single project or a multi-package workspace (check root `package.json` for `workspaces`, or `pnpm-workspace.yaml` / `turbo.json` / `nx.json`). List every package/app and its role (React frontend, Node backend/API, shared libs, scripts, etc.).
2. **Scripts & tooling.** From each `package.json`, record the actual commands for: build, dev, test, lint, type-check, format. Identify the package manager from the lockfile (`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`) and use it consistently.
3. **TypeScript configuration.** Read `tsconfig.json` (and any `tsconfig.*.json` variants): `strict` settings, path aliases (`paths`), project references, module/target. Note any disabled strictness flags (`strictNullChecks`, `noImplicitAny`, etc.) — these matter in Phase 8.
4. **Vite configuration.** Read `vite.config.ts`: aliases (must mirror tsconfig paths), plugins, env handling, build options, proxy config for the Node backend.
5. **Node backend.** Identify the server framework (Express, Fastify, etc.), entry point, route structure, and how the frontend talks to it (fetch wrapper, axios, tRPC, generated client?).
6. **Conventions.** Read the root and per-package `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, ESLint/Prettier configs, and any `docs/` folder. Note the existing shared-code locations (`shared/`, `lib/`, `utils/`, `common/`, `packages/*`).
7. **State & data layer.** Identify the React state approach (Context, Redux, Zustand, TanStack Query, plain hooks) and data-fetching patterns so consolidation targets match the established pattern instead of inventing a new one.
8. **Test setup.** Identify the test runner (Vitest, Jest, Playwright, etc.), where tests live, and roughly what coverage exists, so refactors can lean on tests where they exist and tread carefully where they don't.

**Output of Phase 0:** a short "Repo Profile" summary (stack map, commands, aliases, conventions). All subsequent phases reference this profile.

---

## Phase 1: Automated Baseline

Establish a measurable starting point before changing anything. Run (using the actual commands/package manager from Phase 0):

| Check | Typical command | Purpose |
|---|---|---|
| Type-check | `tsc --noEmit` (per package) | Existing type errors = pre-existing debt, not regressions |
| Lint | `eslint .` or project lint script | Baseline warnings/errors |
| Build | `vite build` / project build script | Must succeed before and after |
| Tests | `vitest run` / project test script | Baseline pass/fail + coverage |
| Dead code & unused deps | `npx knip` | Unused files, exports, types, and dependencies in one pass |
| Circular dependencies | `npx madge --circular --extensions ts,tsx src` | Baseline cycles (don't add more) |
| Bundle size | `npx vite-bundle-visualizer` or rollup-plugin-visualizer | Largest chunks/deps for Phase 6 |
| Dependency audit | `npm audit` / `pnpm audit` + `npx npm-check-updates` (report only) | Security + staleness for Phase 7 |

Record all results. The end-state goal: every number equal or better, with zero behavior change.

---

## Phase 2: Code Review & Correction

Review for genuine defects. These are reported and fixed **separately from refactoring commits**, each with a failing-case description.

- **Type-safety holes:** `any` (explicit or implicit), unsafe `as` casts, `@ts-ignore` / `@ts-expect-error` without justification, non-null assertions (`!`) hiding real nullability.
- **Async/promise bugs:** missing `await`, unhandled rejections, floating promises in event handlers or Express routes, race conditions in effects.
- **React correctness:** missing or wrong `useEffect`/`useMemo`/`useCallback` dependency arrays, state mutations, stale closures, missing cleanup functions, keys derived from array index where order changes, conditional hook calls.
- **Node/API correctness:** unvalidated request input, missing error handling middleware, leaked error details in responses, unclosed resources/handles, blocking synchronous calls (`fs.*Sync`, heavy JSON work) on the request path.
- **Logic errors:** off-by-one, wrong comparison operators, dead branches that indicate a mistake (vs. dead code to delete), copy-paste errors where a variable wasn't renamed.
- **Security quick pass:** secrets committed to the repo, `dangerouslySetInnerHTML` with untrusted input, string-built SQL/shell commands, permissive CORS.

**Output:** a defect table — severity, file:line, description, proposed fix — for approval before fixing.

---

## Phase 3: Dead Code Removal

Using the `knip` results from Phase 1 plus manual inspection, identify and remove:

- Unused files, components, hooks, and modules (never imported anywhere).
- Unused exports and types (exported but never consumed — also check dynamic imports and string-based references before deleting).
- Unreachable branches, commented-out code blocks, and obsolete feature flags whose value can never vary.
- Unused dependencies and devDependencies (cross-check `knip` with actual config files — some tools are referenced only in configs, not imports).
- Orphaned assets, styles, and test fixtures tied to deleted code.
- Leftover scaffolding from abandoned approaches (a common artifact of iterative AI development: v1/v2 copies, `*-old`, `*-backup`, `*.bak`, `Copy of` files).

**Rule:** delete in small commits grouped by area, verifying build + tests after each. Anything ambiguous (possibly used via reflection, env-dependent entry points, public API of a shared package) gets listed for human review instead of deleted.

---

## Phase 4: Duplication Discovery & Consolidation

Scan for duplication introduced through iterative development and produce an inventory:

### 4.1 Duplicate or near-duplicate functions
- Same logic, different names or locations; utilities re-implemented per feature folder; helpers differing only in parameter names or formatting.

### 4.2 Redundant interfaces & types
- Types describing the same shape under different names; subset/superset types that should use `extends`, `Pick`, `Omit`, `Partial`; inline types repeated across files that belong in shared `types/`; frontend/backend types that drift apart and should share a single definition (or be derived from a schema such as zod via `z.infer`, if zod is already in the repo).

### 4.3 Overlapping data-access code
- Multiple fetch/axios wrappers or API clients hitting the same endpoints; duplicated request/response transforms; repeated query keys or cache logic (if TanStack Query is present); Express route handlers repeating the same validation/serialization.

### 4.4 Repeated React patterns
- Components with near-identical JSX/logic that should be one component with props; duplicated form handling and validation; copy-pasted logic across components that belongs in a custom hook; repeated context/provider boilerplate.

### 4.5 Duplicated constants, enums & config
- Magic strings/numbers repeated across files; union types or const-object "enums" defined in multiple places; the same config value defined in both frontend and backend; duplicated env-variable parsing.

### Consolidation plan (per duplicate group)
1. **Canonical location** — single source of truth, placed according to the conventions found in Phase 0 (e.g., `src/shared/utils/date.ts`, `packages/shared/src/types/order.ts`).
2. **Merged signature** — covering all current usages; prefer generics over near-copies; prefer composition over inheritance.
3. **Call-site impact** — every file needing import or argument changes.
4. **Migration steps** — create shared version → migrate call sites → delete duplicates → update barrel exports (`index.ts`) if the repo uses them → verify (type-check, lint, build, test).

**Output format per category:**

| # | Duplicate A | Duplicate B | Proposed canonical | Location | Notes |
|---|---|---|---|---|---|
| 1 | `formatDate()` in `OrderTable.tsx` | `toDateString()` in `invoiceApi.ts` | `formatDate()` | `src/shared/utils/date.ts` | Identical logic, different names |

---

## Phase 5: Behavior-Preserving Refactoring

Beyond deduplication, improve structure without changing what the code does:

- Break up oversized components/modules along clear seams (extract hooks, child components, route handlers) — only where size genuinely harms readability.
- Replace deeply nested conditionals with early returns; flatten promise chains to `async/await`.
- Align file/folder placement with the conventions from Phase 0 (e.g., feature folders vs. type folders — follow whichever the repo already uses; do not reorganize wholesale).
- Normalize import paths to the configured aliases instead of long relative chains (`../../../`).
- Preserve the most complete JSDoc/comments when merging or moving code; keep comments that explain *why*.
- Use TypeScript generics and utility types to unify functions/types that differ only by type parameter.

**Rule:** no abstraction without at least two real, current consumers. Do not introduce speculative layers, wrappers, or patterns "for the future."

---

## Phase 6: Performance & Efficiency Recommendations

Report findings with measured or estimated impact; implement only the approved ones.

**Frontend (React + Vite):**
- Largest bundle contributors (from Phase 1 visualizer): heavy deps with lighter equivalents already feasible, missing route-level code-splitting (`React.lazy` + dynamic import), accidental inclusion of server-only or dev-only code.
- Unnecessary re-renders: unstable props/identities passed to expensive children, missing `memo`/`useMemo` on measured hot paths (do not blanket-memoize), state lifted higher than needed, context values recreated every render.
- Effect hygiene: data fetching in effects that duplicates the query layer, effects that should be event handlers or derived state.
- Asset handling: unoptimized images, fonts without `font-display`, missing compression on the serving layer.

**Backend (Node):**
- Blocking work on the request path; N+1 query patterns; missing pagination on list endpoints; repeated identical upstream calls that could be cached; JSON payloads far larger than the client consumes.
- Per-request construction of things that should be module-level singletons (DB clients, schema validators, compiled regexes).

**Cost angle:** flag anything with direct spend implications — chatty polling vs. websockets/SSE, oversized responses (egress), unindexed hot queries, third-party API calls that could be batched/cached/deduplicated, build pipeline waste in CI.

---

## Phase 7: Dependency & Supply Hygiene

- Remove unused dependencies (from Phase 3) and replace trivially small deps with native code where a one-liner suffices (report, don't auto-replace).
- Flag duplicated functionality across deps (e.g., two date libraries, two HTTP clients, lodash + native equivalents).
- Report security advisories from the audit with severity and whether a non-breaking upgrade exists.
- Report majorly outdated packages; propose upgrades only as a separate, opt-in effort (never mixed into refactor commits).
- Verify `engines`, lockfile integrity, and that frontend/backend don't pin conflicting versions of shared packages.

---

## Phase 8: Best Practices & Conventions

Compare the codebase against the standards it claims (Phase 0 configs) and modern TS/React/Node practice:

- **TypeScript strictness:** if strict flags are off, report what enabling each would surface and propose an incremental path (per-folder or per-flag), not a big-bang change.
- **ESLint/Prettier:** ensure configs exist, are applied in CI, and include `typescript-eslint`, `eslint-plugin-react-hooks`, and (if missing) a rule pass for floating promises. Report rule violations rather than mass-autofixing in one commit.
- **Consistency:** one pattern each for error handling, API responses, env access, logging, and date handling — flag deviations from the dominant pattern.
- **React:** function components + hooks throughout, controlled/uncontrolled form consistency, accessibility basics (labels, button semantics, alt text) flagged where absent.
- **Node:** centralized error middleware, input validation at the boundary, structured logging, graceful shutdown.
- **Git/CI hygiene:** recommend (don't implement without approval) type-check + lint + test in CI if absent.

---

## Phase 9: Documentation Updates

- Update `README.md`(s) so setup, scripts, env vars, and architecture notes match post-cleanup reality. Every documented command must actually work.
- Create or update `CLAUDE.md` (or `docs/architecture.md`) recording: workspace layout, where shared code lives, established patterns (state, data fetching, error handling), and the conventions enforced in this cleanup — so future AI-assisted sessions stop reintroducing duplication.
- Add/refresh JSDoc on consolidated shared utilities and public package exports (the code most likely to be reused).
- Document any intentionally-not-merged near-duplicates (from the Ground Rules) with a comment explaining why they differ.
- Maintain a `CHANGELOG`-style summary of this cleanup: what was removed, consolidated, and recommended-but-deferred.

---

## Phase 10: Final Verification

- [ ] Type-check passes with **no new** errors (ideally fewer than baseline).
- [ ] Lint passes with no new warnings.
- [ ] Production build (`vite build` + backend build) completes with zero errors.
- [ ] Full test suite passes at equal or better coverage than baseline.
- [ ] `knip` reports no unused exports/files/deps in shared modules (or remaining items are documented as intentional).
- [ ] `madge --circular` shows no new cycles.
- [ ] Bundle size is equal or smaller than baseline (report the delta).
- [ ] App boots and a manual smoke test of core flows succeeds (list the flows checked).
- [ ] Docs updated (Phase 9) and final report delivered.

---

## Final Report Format

1. **Repo Profile** (Phase 0 summary).
2. **Baseline vs. final metrics** (type errors, lint, tests/coverage, bundle size, dep count, dead-code count).
3. **Defects found & fixed** (table with severity).
4. **Dead code removed** (file/export counts, LOC deleted).
5. **Consolidations performed** (tables per category, as in Phase 4).
6. **Recommendations deferred for approval** — performance, cost, dependency upgrades, strictness improvements — each with estimated effort and impact.
7. **Conventions recorded** for future development sessions.

---

## Scope Control

- Only consolidate code that is genuinely duplicative. Code that looks similar but serves different domains stays separate, with the difference documented.
- Do not add features, new error-handling semantics, or abstractions beyond what exists.
- Do not reorganize the folder structure wholesale; align stragglers to the existing dominant convention only.
- Limit each pass to one logical area (e.g., "date utilities," "order types," "API client") so every PR stays reviewable.
- Anything risky, ambiguous, or behavior-adjacent goes in the report as a recommendation — not into a commit.
