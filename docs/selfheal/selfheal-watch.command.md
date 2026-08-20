---
description: One self-heal cycle — sweep health/logs/edge/security, update the ledger, Tier-0 auto-remediate (by SELFHEAL_MODE), and report new/unhealed findings.
---
Run one OpenIDX self-heal cycle and report.

1. Run `bash scripts/selfheal/selfheal-watch.sh` and read its summary.
2. Read `oidx-runtime/selfheal/ledger.jsonl`. For any finding that is NEW
   (count==1) or NOT recovering (still `status:open` after remediation) with
   severity `high`/`crit`:
   - `ops` class: confirm the remediator's action (or, if it escalated, say why
     and what a human should do).
   - `bug`/`anomaly` class: note it as a candidate for `/selfheal-triage`
     (do NOT fix here — this cycle is observe/report + Tier-0 ops only).
   - `security` class: summarize the signal; never auto-act.
3. Output a short status: mode, counts by class/severity, what was remediated,
   and anything that needs a human. Do not take Tier-1/Tier-2 actions here.

Guardrails: honor `oidx-runtime/selfheal/DISABLE` (kill-switch) and
`SELFHEAL_MODE`. This command must not deploy, migrate, or edit code.
