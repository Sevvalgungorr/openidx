# Sub-project B — Design System & Shell Completion (Design Spec)

**Date:** 2026-08-22
**Part of:** `docs/ux-audit/2026-08-21-ui-program-roadmap.md` (Wave 2). Builds on Sub-project A (PR #795).
**Solves:** #5 (design system half-adopted, dark mode undeliverable), #7 (no responsive shell, no breadcrumbs, spinners-over-skeletons).

**Goal:** make the console visually consistent and usable everywhere — deliver dark mode, migrate hand-rolled UI to primitives, and complete the shell (responsive + breadcrumbs + skeletons) — locked in by CI guards.

## Key discovery
Dark-mode infrastructure ALREADY exists: `tailwind.config` `darkMode:'class'`, a full HSL token + `.dark` palette in `src/index.css`, theme state in `src/lib/store.ts` (`theme: light|dark|system` + localStorage), and `src/App.tsx` already toggles the root `.dark` class from theme + system preference. **What's missing:** (a) a toggle UI, and (b) pages respond to it — 89 pages hardcode neutral/brand literals (`bg-white`, `text-gray-*`, `border-gray-*`, `text-blue-600`) that ignore the tokens, so dark mode is defined but not delivered.

## Architecture
Behavior/visual only; no new features, no IA changes (that's D). Three new shell primitives + two mechanical sweeps + two guards. In `web/admin-console/src/`.

## Units

### 1. Theme toggle (`ThemeToggle`)
`src/components/theme-toggle.tsx`: a dropdown/segmented control (Light/Dark/System) driven by the EXISTING `useAppStore().theme`/`setTheme`. Mounted in the shell header. No new state system — reuse store.ts + App.tsx's existing `.dark` application.

### 2. `Skeleton` primitive + adoption
`src/components/ui/skeleton.tsx`: a token-based `animate-pulse bg-muted rounded` block + a `TableSkeleton`/`ListSkeleton` helper. Adopt on the highest-traffic primary lists (dashboard, users, and the main list pages) as the loading state; the QueryGate loading fallback may optionally accept a skeleton. Not mandated on all 110 pages (YAGNI) — provide + adopt on a representative set.

### 3. `Breadcrumbs`
`src/components/breadcrumbs.tsx`: derives the trail from the current route + the nav config (`src/config/navigation.ts` domain→section→item) so deep pages show "Domain / Page". Rendered in the shell (top of the content area) for all routes except the dashboard root.

### 4. Responsive shell (`layout.tsx`)
`src/components/layout.tsx`: the `<aside>` sidebar currently has no breakpoints. Add: on `< md`, the sidebar becomes an off-canvas drawer (hidden by default, toggled by a hamburger in the header, with an overlay); on `>= md`, current behavior. Token-ize the shell's hardcoded literals (`bg-white`→`bg-background`/`bg-card`, `text-gray-*`→`text-muted-foreground`, `border`→`border-border`) so the shell itself is dark-correct. Add the `ThemeToggle` + hamburger to the header.

### 5. Token sweep (dark-mode delivery)
Mechanical replacement across the 89 offender pages of the dark-mode-breaking NEUTRAL + BRAND literals with tokens:
`bg-white`→`bg-background`, `text-gray-900|800|700`→`text-foreground`, `text-gray-600|500|400`→`text-muted-foreground`, `bg-gray-50|100`→`bg-muted`, `border-gray-200|300`→`border-border`, `text-black`→`text-foreground`, `text-blue-600`→`text-primary`, `bg-blue-600`→`bg-primary`, `hover:bg-blue-700`→`hover:bg-primary/90`. (Note: `--card` == `--background` in both palettes, so `bg-white`→`bg-background` is safe everywhere.) SEMANTIC STATUS colors (red/green/yellow/amber for error/success/warning/badges) are LEFT AS-IS — they carry meaning and read acceptably in dark; scoping them out keeps this bounded and correct.

### 6. Table migration
Migrate the 27 hand-rolled `<table>` pages to the shared `components/ui/table` (`Table/TableHeader/TableBody/TableRow/TableHead/TableCell`). Preserves behavior; gains consistent styling + dark-correctness + a11y.

### 7. Guards (repo-idiomatic `check-*.sh` + `*.test.sh`)
- `scripts/check-no-raw-neutral-literals.sh` — flags pages using the dark-breaking neutral/brand literals above (allowlist for any intentional case). Warn → enforce.
- `scripts/check-no-handrolled-tables.sh` — flags `<table` in `src/pages`. Warn → enforce.
Both mutation-tested; wired into the existing `ui-safety-guards` CI job (or a sibling job).

## Sequencing (waves)
- **B0** — primitives (ThemeToggle, Skeleton, Breadcrumbs) + guards (warn).
- **B1** — responsive shell + token-ize + mount toggle/breadcrumbs/hamburger.
- **B2** — token sweep across 89 pages (batched by domain; each verified by build + guard-count-drop + page tests).
- **B3** — table migration across 27 pages (batched).
- **B4** — skeleton adoption on primary lists.
- **B5** — flip guards to enforce; final verification.

## Testing
Unit tests for ThemeToggle (switches store theme), Breadcrumbs (derives trail for a sample route), Skeleton (renders). Shell: a test that the drawer opens/closes at mobile widths (jsdom-limited — assert the toggle state + classes). Sweeps verified by: `tsc`, `npm run build`, the two guards, and the existing ~859 page tests (must stay green). A visual spot-check isn't automatable headlessly — the token mapping is conservative (neutrals only) to keep risk low.

## Success criteria (measurable)
1. A working Light/Dark/System toggle; the shell + all `components/ui/*` render correctly in dark.
2. Guard 1 (raw neutral/brand literals) at 0 → pages respond to dark mode.
3. Guard 2 (hand-rolled tables) at 0 → all pages use `ui/Table`.
4. Responsive: sidebar becomes a drawer below `md`; usable at 375px.
5. Breadcrumbs on all deep routes; Skeleton primitive shipped + adopted on primary lists.
6. 859+ tests green; both guards enforce-green in CI.

## Out of scope (later waves)
Topology/cockpit (C); merging duplicate pages / insight actionability (D); a full skeleton rollout to every page (provide + representative adoption only). No component API redesign of existing `ui/*` primitives.
