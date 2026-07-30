# Wazuh Integration — Open-Source EDR for Device Posture

OpenIDX's EDR posture pipeline previously supported only commercial sources
(CrowdStrike, Intune, Jamf). With the `wazuh` provider, the whole
device-posture chain — *endpoint agent → EDR verdict → Ziti posture check →
overlay enforcement* — runs on fully open-source, self-hosted components.

## How it fits

```
┌──────────────┐  agent enrolls   ┌───────────────┐  REST API   ┌───────────────┐
│  Endpoint    │ ───────────────► │ Wazuh manager │ ◄────────── │ access-service│
│ (Wazuh agent │                  │ (self-hosted, │  /agents    │  EDR ingest   │
│ + OpenIDX    │                  │  port 55000)  │             │  worker       │
│ agent)       │                  └───────────────┘             └──────┬────────┘
└──────────────┘                                                       │ posture result
                                                                       ▼
                                          device_posture_results → Ziti posture check
                                          → continuous-verify → session/circuit sever
```

- **Yes, the Wazuh agent installs directly on endpoints** (Linux, Windows,
  macOS packages) and enrolls against your Wazuh manager — that part is
  standard Wazuh, nothing OpenIDX-specific. The endpoint also runs the OpenIDX
  agent for its Ziti identity; the two are correlated by **hostname**.
- OpenIDX never talks to endpoints for this — it pulls fleet health from the
  **manager's** REST API on the ingest worker's poll interval.

## Compliance mapping

| Wazuh agent status | Posture verdict | Why |
|---|---|---|
| `active` | **pass** (risk: low) | Agent alive and reporting — endpoint under EDR coverage |
| `disconnected` | **fail** (risk: high) | Endpoint dropped off EDR coverage — exactly what zero trust must catch |
| `never_connected` / `pending` | **fail** (risk: unknown) | Enrolled but not yet protected |

Agent `000` (the manager itself) is skipped. A failing verdict lands in
`device_posture_results` against the matched Ziti identity, and the existing
continuous-verify enforcement severs the session — no new enforcement code.

## Setup

1. **Run Wazuh** (or use an existing install). Any deployment shape works —
   OpenIDX only needs HTTPS reachability to the manager API
   (`https://<manager>:55000`).
2. **Create an API user** in Wazuh with read access to agents
   (`agent:read`), e.g. via the Wazuh RBAC UI.
3. **Register the source** in OpenIDX (admin API):

   ```bash
   curl -X POST /api/v1/access/ziti/posture/edr \
     -H 'Content-Type: application/json' \
     -d '{
       "name": "wazuh-prod",
       "provider": "wazuh",
       "base_url": "https://wazuh-manager.internal:55000",
       "api_user": "openidx-reader",
       "api_token": "<password>",
       "posture_check_id": "<ziti posture check to record against>",
       "enabled": true
     }'
   ```

   `match_strategy` defaults to **hostname** for Wazuh (agents report no
   serial/email; the agent name defaults to the endpoint hostname and is
   matched against the OpenIDX agent's reported hostname in
   `enrolled_agents.metadata`).
4. **Test** with `POST .../posture/edr/:id/test`, then let the poller run (or
   trigger `POST .../posture/edr/:id/sync`).

## Notes

- **TLS**: the manager API certificate must be trusted by the access-service —
  mount the Wazuh root CA into the container trust store. Verification is
  never skipped, consistent with the platform's production TLS posture.
- **Credentials** are AES-encrypted at rest like all EDR sources
  (`edr_posture_sources.api_token_enc`) and never returned by the API.
- The Wazuh API JWT is short-lived; the connector re-authenticates on every
  sync pass, so no token storage is needed.
- Wazuh's richer signals (SCA score, vulnerability counts, active-response
  state) are natural follow-ups — the connector's `Raw` details blob already
  carries `status`, `ip`, and `os` per device for the posture-result record.
