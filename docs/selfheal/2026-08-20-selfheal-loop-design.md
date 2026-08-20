# OpenIDX Self-Healing & Self-Improving Ops Loop — Design

## Context

OpenIDX runs on a single box as 7 systemd `--user` services plus podman infra
(pg, redis, apisix, nginx, ziti, prometheus). Operations today are manual and
reactive: incidents (e.g. the frontend `dist`-rename that took the SPA down with
a 403, or the auto-trust bug that silently read config as `off`) are only found
when a human looks. Logs flow to `/tmp/oidx-logs/*.log` as structured zap JSON
but are never analyzed; there is Prometheus but no log aggregation; there is a
strong existing tradition of deterministic `check-*.sh` / `*-score.sh` probe
scripts, CodeQL for code security, and Claude Code cron/routines for scheduling.

Goal: turn OpenIDX into a product that watches, heals, and hardens itself —
a Claude-driven loop that continuously checks health + log liveness, analyzes
logs for bugs/anomalies/security issues, remediates automatically within a strict
safety envelope, and improves its own coverage over time.

**Agreed product decisions:**
1. **Full autonomy, with guardrails** — the loop may analyze → fix → test →
   deploy on its own, but only inside a safety envelope (backup-first, canary,
   health-gate, auto-rollback, blast-radius caps, kill-switch). Destructive /
   irreversible changes stay human-gated (Tier-2).
2. **All facets in scope** — health + log-liveness + ops-remediation + log
   analysis/bug-detection + security-from-logs — as one program, phased.
3. **Scheduled Claude cron/routines** drive it.
4. **Approach C (hybrid)** — cheap deterministic collectors feed intelligent
   Claude routines, backed by a git-tracked findings ledger.

**Design principle:** intelligence (analysis + decision) lives in Claude
routines; signal collection is cheap/deterministic (no Claude); the box is
mutated in exactly ONE place (the remediator) so every guardrail lives together.

Namespace: `scripts/selfheal/`, state: `oidx-runtime/selfheal/`, docs:
`docs/selfheal/`.

## Architecture

```
[Collectors]──JSON snapshot──▶[Ledger]──▶[Claude routines]──▶[Remediator]──▶ box
 (cheap, box-local)          (memory)     (analyze/decide)   (only mutation point)
        ▲                                                            │
        └───────────────── health verify / rollback ◀───────────────┘
```

Five units, each single-purpose and independently testable:

### 1. Collectors — `scripts/selfheal/collect-*.sh` + `sweep.sh`
Deterministic, box-local, cheap (grep/awk/curl; no Claude). `sweep.sh` runs the
collectors and writes one JSON snapshot to `oidx-runtime/selfheal/latest.json`
(plus a timestamped copy). Signals:
- **health** — per service `/health` status + version + `NRestarts` + systemd
  unit active-state; infra container states.
- **log-liveness** — mtime/size delta per `/tmp/oidx-logs/<svc>.log`; a stale log
  (not growing) is itself a finding (a service wedged/not logging).
- **log-signal** — error/panic/fatal counts per service over the last window +
  the top error messages, grouped by a normalized fingerprint (strip
  ids/timestamps), with new-vs-seen classification.
- **edge** — SPA `/`, `/api/v1/...`, OIDC, `/downloads/...`, audit-WS handshake
  reachability through APISIX `:443` (catches edge/routing/mount breakage).
- **security** — 401/403 rates, auth-failure spikes, injection/traversal
  patterns, privilege-escalation attempts, config-drift (dev-mode in prod,
  unexpected open ports — reuses `audit-listening-ports.sh`).
- **resources** — disk (log dir + backups), restart-loop detection.

Extends the existing `field-fix-score.sh` / `audit-listening-ports.sh` gene.

### 2. Findings Ledger — `oidx-runtime/selfheal/ledger.jsonl` + `docs/selfheal/known-issues.md`
Append-only. Every finding is deduped by a **fingerprint** (class + normalized
signature). Each record: fingerprint, class (ops|bug|anomaly|security), severity,
first_seen, last_seen, count, status (open|remediating|resolved|escalated),
action_taken, outcome. This is the memory that powers self-improvement (a
recurring fingerprint → a permanent fix). `known-issues.md` is the
human-readable, git-tracked digest.

### 3. Claude Routines (scheduled, tiered cadence)
Each is a skill/slash-command run by a Claude cron:
- **`/selfheal-watch` (~15 min)** — run `sweep.sh` → diff snapshot vs baseline +
  ledger → classify NEW/worsening findings → auto-remediate Tier-0 ops issues →
  update ledger → notify on high-severity. Only escalates to deep analysis on a
  new/unresolved finding, so most runs are cheap.
- **`/selfheal-triage` (hourly / on escalation)** — deep root-cause on flagged
  bugs/anomalies from the logs → produce a fix (reproduce → patch → test) →
  guardrail-deploy → PR. The code-fix tier.
- **`/selfheal-security` (daily + on security spike)** — correlate log security
  signals + audit + CodeQL + config-drift → hardening PR / active-threat alert.
- **`/selfheal-review` (daily/weekly)** — read the ledger → turn recurring or
  systemic findings into permanent improvements (a code PR, a new collector
  check, or a runbook). The self-improvement engine.

### 4. Remediator — `scripts/selfheal/remediate.sh`
The only component that mutates the box. Tiered autonomy + safety envelope below.

### 5. Scheduler — Claude cron/routines
Runs the routines at their cadences; escalates/notifies on high-severity.

## Safety envelope & tiered autonomy

The remediator classifies every action by reversibility/risk:

- **Tier-0 — Ops (auto, deterministic, idempotent; no code change):** restart a
  dead/crash-looping unit; `systemctl --user start` a down infra container;
  restart nginx / re-establish a broken mount (the yesterday-incident class);
  rotate a full log; clear a stuck healthcheck. Each: pre-check → act → **health
  verify** → rollback on failure → record.
- **Tier-1 — Code/config fix (autonomous, full guardrails):** reproduce → patch →
  `go build`+`vet`+`test` → **backup** → build in an isolated worktree → migrate
  if needed → **canary** (swap one service, health-gate) → roll the rest →
  **auto-rollback on any health failure** → PR for record. Frontend deploys
  rsync-in-place / restart nginx (never rename the bind-mounted `dist`).
- **Tier-2 — Human approval (NOT autonomous):** schema-destructive migrations,
  RBAC/secret/edge-route changes, or anything exceeding the blast-radius cap →
  never auto-applied; emits a PR + notification. (The classifier blocking
  yesterday's APISIX-route and super_admin changes is this tier in practice.)

Guardrails applied to **every** mutation:

| Guardrail | Behavior |
|-----------|----------|
| Backup-first | pg_dump + binary `.rollback-<ts>` copies (existing deploy recipe) |
| Health-gate + auto-rollback | every restart/swap verifies `/health`; reverts on failure |
| Blast-radius cap | ≤2 services and ≤1 migration per run; larger → escalate to Tier-2 |
| Anti-flap / rate-limit | auto-remediate a fingerprint at most **K=3 times/hour** (configurable), then escalate to Tier-2 (prevents restart/fix loops) |
| Kill-switch | `oidx-runtime/selfheal/DISABLE` file halts all autonomous action instantly |
| Autonomy gate | `SELFHEAL_MODE = off \| observe \| tier0 \| tier1` (mirrors the codebase's `off/observe/enforce` gates) |
| Always-notify | every Tier-1 action + every high-severity finding is reported (human stays in the loop even under full autonomy) |

Why this is safe: anything destructive/irreversible is Tier-2 (not automatic);
anything automatic is either idempotent ops (Tier-0) or backup+canary+auto-
rollback-armored (Tier-1); blast-radius + anti-flap cut runaway; the kill-switch
and staged mode (`observe`→`tier0`→`tier1`) keep enablement in the user's hands.

## Self-improvement

`/selfheal-review` reads the ledger and:
- **Recurring fingerprint** (same issue across **N=3 runs**, configurable) → proposes a **permanent
  fix** (root-cause code PR, a new collector check so it's never silent again, or
  a runbook) instead of repeatedly remediating the symptom.
- **Blind-spot detection** — if an incident was NOT caught by the collectors
  (e.g. the nginx-mount outage showed only an empty `<title>`), it authors a
  **new check** that would catch it next time. The system grows its own
  observability after every incident.
- Output: updates `docs/selfheal/known-issues.md` + a hardening PR when warranted.

## Security-from-logs

Part of the security collector + `/selfheal-security` correlation:
- Auth abuse: per-IP/user 401/403 spikes, brute-force / credential-stuffing
  patterns, abnormal time/geo.
- Injection/traversal attempts in request logs; privilege-escalation attempts
  (the class the recent authz sweep found).
- Config-drift: dev-mode in prod, unexpected open ports (`audit-listening-ports.sh`
  gene), cross-checked with CodeQL alerts.
- Active-threat signals → immediate alert (never silent auto-fix); hardening →
  Tier-1/Tier-2 PR.

## Testing

- Each collector has a test following the repo's existing `check-*.sh ↔
  check-*.test.sh` pairing.
- The remediator's safety-envelope logic (blast-radius, anti-flap, kill-switch,
  health-gate/rollback) is unit-tested and has a **`--dry-run`** mode that logs
  what it WOULD do without acting.
- Ledger dedup/fingerprint logic is tested.

## Phased rollout (mirrors `off/observe/enforce`)

1. **`observe`** — collectors + ledger + notifications run; **no mutation**. Watch
   for a few days.
2. **`tier0`** — enable ops remediation (unit/nginx/log).
3. **`tier1`** — enable autonomous code-fix (backup+canary+rollback armored).

Each step is separate and reversible; the kill-switch applies at all times.

## MVP scope (this implementation plan)

`sweep.sh` + the 5-6 collectors · ledger + fingerprint · `remediate.sh` (Tier-0 +
safety envelope + `--dry-run`) · a `/selfheal-watch` skill + one Claude routine
(15 min, starting in `observe` mode) · collector/ledger/remediator tests ·
`docs/selfheal/` runbook. The triage / security / review routines and the full
Tier-1 harness are **phase 2** on the same skeleton.

## Verification (how to test end-to-end)

- Run `sweep.sh` on the box → a well-formed `latest.json` with all signal groups.
- Simulate a stopped unit / a stale log / an edge 500 → the collector flags it,
  the ledger records it, and (in `tier0`) the remediator restarts/reloads and the
  health-gate confirms recovery; in `observe` it only records + notifies.
- `remediate.sh --dry-run` on a seeded finding prints the intended action without
  touching the box.
- Trip the kill-switch → the next `/selfheal-watch` run takes no action.
- Seed a synthetic security pattern (401 spike) → `/selfheal-security` reports it.
