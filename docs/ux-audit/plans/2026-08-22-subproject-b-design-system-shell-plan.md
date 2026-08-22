# Sub-project B — Design System & Shell Completion Implementation Plan

> **For agentic workers:** subagent-driven. Steps use checkbox tracking.

**Goal:** deliver dark mode (toggle + token sweep), migrate hand-rolled tables to primitives, and complete the shell (responsive drawer + breadcrumbs + skeletons), enforced by two CI guards.

**Architecture:** reuse the existing theme infra (store.ts theme + App.tsx `.dark` application). Build 3 shell primitives + 2 mechanical sweeps + 2 guards. Behavior/visual only.

**Tech:** React+TS, tailwind (`darkMode:'class'`, HSL tokens in index.css), vitest. Commands from `web/admin-console`. Commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

**Spec:** `docs/ux-audit/specs/2026-08-22-subproject-b-design-system-shell-design.md`

## Token mapping (used by the sweep + Guard 1)
`bg-white`→`bg-background` · `text-gray-900|800|700`→`text-foreground` · `text-gray-600|500|400`→`text-muted-foreground` · `bg-gray-50|100`→`bg-muted` · `bg-gray-200`→`bg-muted` · `border-gray-200|300`→`border-border` · `text-black`→`text-foreground` · `text-blue-600`→`text-primary` · `bg-blue-600`→`bg-primary` · `hover:bg-blue-700`→`hover:bg-primary/90`. Leave semantic red/green/yellow/amber status colors as-is.

---

### Task 1: ThemeToggle
- Create `src/components/theme-toggle.tsx` (+ test). Uses `useAppStore()` `theme`/`setTheme` (from `src/lib/store.ts`). A dropdown-menu (Light/Dark/System) with Sun/Moon/Monitor icons.
- Test: renders; clicking an option calls `setTheme` with that value (mock the store).
- Commit `feat(ui): ThemeToggle (light/dark/system)`.

### Task 2: Skeleton primitive
- Create `src/components/ui/skeleton.tsx` (+ test): `Skeleton` (`animate-pulse rounded-md bg-muted`), plus `TableSkeleton({rows,cols})`.
- Test: renders N rows.
- Commit `feat(ui): Skeleton + TableSkeleton primitive`.

### Task 3: Breadcrumbs
- Create `src/components/breadcrumbs.tsx` (+ test): given the current pathname, find the matching nav item in `src/config/navigation.ts` and render `Domain / Item`. Hidden on `/` and `/dashboard`.
- Test: for a known route (e.g. `/users`) renders the IAM domain + "Users"; renders nothing for `/dashboard`.
- Commit `feat(ui): Breadcrumbs derived from nav config`.

### Task 4: Guards (warn) + CI
- `scripts/check-no-raw-neutral-literals.sh` + `.test.sh`: flag pages matching `bg-white|text-gray-[0-9]|bg-gray-[0-9]|border-gray-[0-9]|text-black|text-blue-600|bg-blue-600` (allowlist param). Warn default, `--enforce`.
- `scripts/check-no-handrolled-tables.sh` + `.test.sh`: flag `<table` in `src/pages/*.tsx`.
- Add both to the `ui-safety-guards` CI job (self-tests + warn report).
- Commit each.

### Task 5: Responsive shell + token-ize `layout.tsx`
- Modify `src/components/layout.tsx`: add mobile drawer (`< md`: `<aside>` fixed off-canvas, translate-x toggled by a hamburger button in the header + a click-catching overlay; `>= md`: current static sidebar). Token-ize the shell literals (`bg-white`→`bg-background`/`bg-card`, `text-gray-*`→tokens, `border`→`border-border`). Mount `<ThemeToggle/>` + hamburger in the header; render `<Breadcrumbs/>` at the top of the content area.
- Verify `tsc` + `build` + `layout` test (if any) + manual class check. Commit `feat(ui): responsive shell (mobile drawer) + theme toggle + breadcrumbs + token-ize`.

### Task 6 (B2): token sweep — 89 pages, batched by domain
- Apply the token mapping across `src/pages` offenders. Batch (~15/agent), one commit per page or per small group; each batch: `tsc` + `build` + affected page tests green + Guard-1 count drops. Semantic status colors untouched.
- Gate: Guard 1 → 0.

### Task 7 (B3): table migration — 27 pages, batched
- Migrate hand-rolled `<table>` to `components/ui/table`. Batch (~9/agent). Each: `tsc` + `build` + page tests green. Gate: Guard 2 → 0.

### Task 8 (B4): skeleton adoption
- Adopt `TableSkeleton`/`Skeleton` as the loading state on the primary list pages (dashboard, users, groups, roles, applications, audit-logs, and the main dashboards) — a representative set, not all 110.
- Commit per page or grouped.

### Task 9 (B5): enforce
- Flip both new guards to `--enforce` in CI. Verify both at 0 locally. Full `npx vitest run` green, `tsc`, `build`. Commit `ci(ui): enforce design-system guards`.

## Success criteria
Toggle works; Guard 1 (literals) = 0; Guard 2 (tables) = 0; drawer works < md; breadcrumbs on deep routes; Skeleton adopted on primary lists; 859+ tests green; guards enforce-green.
