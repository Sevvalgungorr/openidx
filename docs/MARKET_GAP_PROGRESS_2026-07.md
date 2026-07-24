# §7.2 Market-Gap Closure — Progress & Remaining Waves

Status snapshot after the 2026-07-23 push. This tracks the §7.2 roadmap from
`docs/MARKET_REANALYSIS_AND_GTM_2026-07.md`.

## Closed this cycle (all merged to main + live-verified)

| Gap / Wave | PR | What shipped |
|-----------|----|--------------|
| Outbound SCIM client | #543 | OpenIDX provisions users/groups OUT to Okta/Entra/Slack/... (SCIM 2.0 client, outbox worker, fan-out on inbound writes) |
| HR-driven JML | #544 | BambooHR source of truth for joiner/mover/leaver (directory-connector type; manager resolution; safety valve) |
| Token Exchange (RFC 8693) + DCR (RFC 7591/7592) | #545 | Agent-identity substrate: token exchange with delegation `act`, dynamic client registration + management |
| EDR/MDM posture ingestion | #546 | CrowdStrike/Intune/Jamf device compliance → the Ziti-bound posture pipeline (non-compliant device → circuit cut) |
| SSF/CAEP transmitter + receiver | #547 | First OSS SSF/CAEP with native network termination (receiver actuator severs the overlay) |
| Mid-session + governance-revoke network termination (A3 + B2) | #549 | Posture/risk degrade AND access-review/cert/JIT revoke sever live Ziti circuits |
| JIT network grants (B1) | #551 | Approve a network_service request → time-bound `jit-<id>` Ziti attribute opens the dial → expiry removes it + severs the circuit |
| Usage metering (A4) | #553 | Daily rollup of Ziti fabric usage (overlay logins, service dials) per org/service/identity from unified_audit_events; GET /api/v1/audit/usage |
| MCP / AI-agent gateway (D1) | #555 | Agent token → per-tool allowlist → forward to MCP server over dark Ziti service → audited. Network-enforced agent containment. |

Migrations v95–v104 applied live. Every feature has DB-backed tests + a live
end-to-end proof against `openidx.tdv.org`.

## §7.2 waves — now CLOSED

### A2 — Per-org overlay scoping (MSP unlock) ✅ (#563, migration v104)
Per-org isolation on the overlay, behind the `ZITI_PER_ORG_ATTRIBUTES` flag
(default off → single-tenant installs unchanged):
- `groups` composite `UNIQUE(org_id, name)` (v104) so two tenants can own
  identically named groups.
- Group role attributes namespaced `org-<id>-<group>`; each identity tagged with a
  bare `org-<id>` marker.
- Reconciler emits a per-org Dial policy `openidx-orgdial-<svc>` granting only
  `#org-<id>`, so a tenant's users can dial only their own org's services.
- Live-proven: two orgs both hold a `Platform` group → distinct attributes +
  markers; SQL transform matches the Go code; flag-off deploy left the overlay
  healthy (router online, no orgdial policies emitted).

### D3 — K8s fabric subchart + HA controller (Raft) + Terraform ✅ (#564)
Production packaging for the overlay, disabled by default:
- Helm `templates/ziti-fabric.yaml`: controller StatefulSet (HA/Raft when
  `controller.replicas>=3`, per-replica PVC), edge router Deployment, Services
  (client 1280 / edge 3022 / optional BrowZer 3023).
- Terraform `modules/openziti`: helm_release wrapper toggling `zitiFabric.*`,
  `ha_enabled` output, wired into `main.tf` (prod → 3 controllers / 2 routers).
- Validated: `helm lint` clean, `helm template` renders (Raft env at replicas=3),
  `terraform fmt`/`validate` clean. Ships as validated manifests (no live cluster).

## Notes for the next session

- Workers now running in access-service: EDR ingestion, network revocation.
  In oauth-service: SSF push. In provisioning-service: outbound SCIM.
- The `network_revocation_queue` (v100) + `severUserZitiCircuits` are the shared
  actuator for any "sever this user's circuits" need — reuse them for B1's
  kill-on-expiry and any future revocation source.
- All new secrets are encrypted via `secretcrypt` (needs `ENCRYPTION_KEY`).
