# Self-Heal Loop — Runbook

## What it is
A Claude-driven ops loop. Deterministic collectors emit findings → a
fingerprint-deduped ledger → the remediator applies Tier-0 fixes inside a safety
envelope. See `docs/selfheal/2026-08-20-selfheal-loop-design.md`.

## Files
- `scripts/selfheal/` — collectors, sweep, ledger, remediate, selfheal-watch (+ tests)
- `oidx-runtime/selfheal/` — runtime state: `latest.json`, `ledger.jsonl`, `MODE`, `DISABLE`, `flap`
- `.claude/commands/selfheal-watch.md` — the Claude routine entry

## Controls
- **Mode:** `echo tier0 > oidx-runtime/selfheal/MODE` (off | observe | tier0 | tier1). Default observe.
- **Kill-switch:** `touch oidx-runtime/selfheal/DISABLE` halts ALL autonomy. Remove to resume.
- **Manual run:** `bash scripts/selfheal/selfheal-watch.sh`
- **Dry-run remediation:** `bash scripts/selfheal/sweep.sh | bash scripts/selfheal/remediate.sh --dry-run`

## Rollout
1. `observe` (default) — detect + record + report, no mutation. Watch a few days.
2. `tier0` — enable ops remediation (restart unit / nginx, etc.).
3. `tier1` — enable autonomous code-fix (phase 2; backup+canary+rollback armored).

## Tiers
- Tier-0 (auto): restart dead unit, restart nginx (SPA mount fix), etc.
- Tier-1 (auto, guardrailed, phase 2): code/config fix → test → canary deploy → rollback.
- Tier-2 (human): schema-destructive migrations, RBAC/secret/edge-route changes, blast-radius overflow.
