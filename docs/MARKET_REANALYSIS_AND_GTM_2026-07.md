# OpenIDX — Market Re-Analysis, Ziti-First Strategy & Go-To-Market (2026-07-21)

> **What this is.** The commercial follow-on to
> [`MARKET_GAP_ANALYSIS_2026.md`](./MARKET_GAP_ANALYSIS_2026.md) (2026-07-10 gap
> register) and [`ULTIMATE_PRODUCT_PLAN.md`](./ULTIMATE_PRODUCT_PLAN.md) (product
> roadmap). Those answered *"what to build."* This document answers four
> commercial questions as of **2026-07-21**:
>
> 1. **How ready is the project now?** — re-scored against the live code after
>    the 59 commits (v1.25.0 → v1.27.0+, schema v68 → v87) that landed since the
>    July 10 audit.
> 2. **What is the product thesis "over Ziti"?** — which features to set on top
>    of the OpenZiti layer, and why that stack is the moat.
> 3. **How does governance affect IAM, Ziti, and PAM?** — the control-plane
>    model that makes the four pillars one product instead of four modules.
> 4. **How do we sell it?** — segments, packaging, pricing, channels, and a
>    sequenced 12-month commercialization path — plus the refreshed gap list,
>    split into *deal-blockers* and *product gaps*.
>
> Method: code-verified internal audit (sentinel checks against the July 10
> register + a full implementation-maturity sweep) plus fresh July-2026 market
> research (competitive landscape, OpenZiti ecosystem, commercial-OSS GTM
> benchmarks). Sources cited inline where external.

---

## 1. Executive summary

**How ready is the project?** Materially more ready than eleven days ago.
The July 10 audit's central risk — the "hollow layer" of advertised-but-broken
features — is mostly gone: fourteen P0 rows are verified closed in code
(step-up bypass, MFA-factor bypass, inert API keys, tenant IDOR/enumeration,
fail-open SoD, non-enforcing certification revokes, unscoped campaigns, SCIM
filter, key rotation, dead-engine purge), and the platform gained a signed
Windows client, a mobile app, a kill switch spanning token→session→circuit,
RDM-parity PAM with overlay-dark targets, and an executed ops-hardening
sprint (backups+tested restore, observability/SLOs, KEK rotation, single
edge, merge-blocking RLS linter). Verdict: **MVP-to-early-GA — ready for
design partners and paid pilots now**; unqualified GA is blocked by six
Tier-1 landmines (push-MFA delivery on a dead FCM endpoint, unsent
magic-link email, hand-rolled SAML crypto, missing consent screen, a mock
session helper in-tree, stub voice MFA) that are days-to-weeks of work, plus
commercialization scaffolding that is calendar-bound, not code-bound (§2, §7).

**What is the product thesis over Ziti?** Every incumbent is assembling
"identity to network packet" by M&A ($25B PANW×CyberArk closed Feb 2026;
Okta×Axiom; Delinea×StrongDM) — OpenIDX already *is* that, in one codebase
over one Postgres. OpenZiti is the substrate that makes each promise
physical: deprovision severs circuits in ≤30 s, privileged targets have no
inbound port, the kill switch reaches the packet. The build order (§3.3):
first make the network pillar auditable and tenant-clean (fabric-event
ingestion, per-org overlay scoping, mid-session posture revocation,
metering), then wire governance to the network (JIT network grants,
certification-revoke → circuit severance), then modern-PAM on the fabric
(`openidx connect`, secretless injection), then the agent frontier
(MCP gateway, SSF/CAEP). The OSS OpenZiti management plane remains an
unclaimed strategic prize: upstream v2.0 just shipped GA controller HA and
delegation primitives, the official console is vestigial (37 GitHub stars),
NetFoundry is quote-only and frames OSS as non-production — and Headscale
(42k stars) proves open control planes win mindshare (§6.1).

**How does governance affect IAM, Ziti, PAM?** Governance is the decision
layer; the other three are enforcement planes sharing one database — so a
decision propagates as writes and ≤30 s reconciles, not connector tickets.
Approvals/SoD/JIT/certifications already enforce into IAM (grants, session
kills) and PAM (checkout approval, JIT leases, live-session termination);
lifecycle and the kill switch already enforce into Ziti at identity level.
Two wires (JIT network grants, revoke→policy-detach) complete the sentence
that closes deals: *"a revoke decision deletes the grant, kills the session,
terminates the privileged connection, and severs the network circuit in
under 30 seconds — one hash-chained audit trail"* (§4).

**How do we sell it?** Community-led, design-partner-anchored, sovereignty-
first (§8): fix time-to-first-value, launch loudly (Show HN / r/selfhosted —
the Infisical/Authentik funnel), and recruit 5–10 design partners where
regulation forces self-hosting — Türkiye first (BDDK bars SaaS IdPs from
core banking; yerli malı = 15% public-tender advantage; the real rival is
free-Keycloak-plus-SI, so sell the *certified, supported, four-pillar
suite*), then EU NIS2/DORA mid-market (DORA's RTS is effectively a PAM
mandate; no sovereign vendor offers all four pillars), then MSPs
(white-label multi-tenant is unserved in OSS ZTNA) and OSS-first
engineering orgs (Auth0-renewal and Teleport-license refugees). Keep the
core Apache-2.0 forever; monetize new buyer-tier features only
(compliance packs, premium connectors, MSP orchestration/metering,
FIPS/air-gap builds, SLAs) — the 2023–26 license wars prove backlash tracks
retroactive taking, and compliance-grade builds are the best-documented
first-dollar trigger (Chainguard: $5M→$40M ARR). Price Enterprise at
$4–6/user/mo (floor ~$6–8K/yr) against a stacked incumbent bill of
$33–65/user/mo — the README's "70–80% savings" is now substantiated by
third-party pricing data. Trust calendar: pentest now, **CRA
vulnerability-reporting readiness by 2026-09-11** (identity/PAM software is
CRA "Important Class I" by name), ISO 27001 in Q4, SOC 2 Type II before the
first US mid-market deal. Honest math: 0.2–1% of self-hosted orgs convert;
year-two target is 30–60 customers ≈ **$1–2M ARR** — the exact waterline
where Zitadel, NetBird, and Infisical raised or reached sustainability (§8.8).

**The gaps** (§7): six Tier-1 demo landmines (fix before any external eval);
eight commercial deal-blockers (pentest/attestation, README contradiction,
quickstart TTFV, importers, licensing clarity, benchmarks, supply-chain
signing, i18n); and a Tier-2 capability list topped by outbound SCIM (the
one workforce-IAM hole Okta will always exploit), HR-driven JML, fabric
event ingestion, per-org overlay scoping, and the RFC 8693/DCR agent
substrate. The 12-month calendar in §9 sequences all three streams to a
Q2 2027 target of 10 customers and $250–500K ARR run-rate.

---

## 2. Readiness re-assessment (2026-07-21)

### 2.1 What actually changed since the 2026-07-10 audit

The July 10 register's headline risk was the **"hollow layer"** — advertised
features that were dead code or silently broken. Eleven days and 59 commits
later, most of the *exploitable* hollow layer is gone. Verified in code, not
changelogs:

**Security wave (v1.25.0, workstreams WS-01…WS-05) — closed:**

| July 10 finding | Status today (verified) |
|---|---|
| Step-up MFA rubber-stamps any code | **Fixed** — `internal/oauth/stepup.go` now calls `verifyStepUpFactor` (TOTP/WebAuthn verified before minting) |
| MFA challenge only checks TOTP (WebAuthn/SMS-only users bypass) | **Fixed** — `mfaEnabled := hasPrimaryFactor` over all enrolled factors (`internal/oauth/service.go:1947`) |
| API keys can't authenticate (nil validator) | **Fixed** — minted keys now authenticate |
| `GET /organizations` enumerates every tenant | **Fixed** — org write paths authorized, list scoped |
| Elasticsearch audit search leaks cross-tenant | **Fixed** — ES queries tenant-scoped |
| Preventive SoD broken by column mismatch, fails open | **Fixed** — SoD enforced fail-closed at role-grant *and* request-fulfillment (`SoDViolationError`, `internal/governance/workflows.go`) |
| Certification "revoke" doesn't revoke | **Fixed** — revocation enforced + sessions killed on access-review revoke |
| Reviewer always "admin" | **Fixed** — manager-based reviewer resolution live |
| Campaigns/ABAC tables not org-scoped | **Fixed** — org_id + FORCE RLS (migrations v69–v80) |
| SCIM `filter` ignored | **Fixed** — 786-line filter parser compiled to SQL (`internal/provisioning/scim_filter.go`) |
| One eternal signing key, hardcoded `kid` | **Fixed** — DB-backed rotatable RS256 keys (`oauth_signing_keys`, v79) |
| Five parallel risk engines / two OAuth stacks | **Purged** — dead-code purge landed in v1.25.0 |
| Anomaly detection never invoked | **Wired** — `RunAnomalyCheck` invoked via the identity-service adapter (`cmd/identity-service/main.go:329`) |
| Approval escalation only in dead code | **Wired** — request escalation checker runs (`internal/governance/request.go:413`) |

**Cross-pillar convergence (new since July 10):**
- **Access 360** — one API/console view correlating a user's IAM roles/groups,
  PAM grants/checkouts/live sessions, and Ziti identity/devices/policies
  (`docs/IAM_PAM_ZITI_INTERRELATION.md`).
- **The kill switch** — `POST /api/v1/access/users/:id/kill-switch` severs
  IAM sessions + API keys, PAM checkouts/JIT/live Guacamole sessions, and Ziti
  edge+API sessions (circuits) in one action (`internal/access/kill_switch.go`,
  408 LOC). Device-scoped variant exists.
- **Lifecycle propagation** — disable a user by *any* path (API, SCIM,
  directory sync, DB) and three reconcile layers sever all pillars in ≤30 s.
- **Device correlation** — IAM device trust and Ziti agent compliance linked
  per physical device (migration v80).

**Client wave:**
- **Windows client** — full agent: SSO/PKCE desktop auth, PAM, tray, embedded
  Ziti, IPC, real posture checks (BitLocker/firewall/AV/patch/domain), MSI,
  **Authenticode-signed** with CI pipeline, winget manifest, self-update.
- **Mobile app (Expo/React-Native)** — usernameless passkey login, TOTP +
  step-up, push-MFA approve UI, approvals inbox, My Access, PAM self-service,
  device enrollment + posture, native Ziti module scaffold (Swift + Kotlin).
- **Android agent** (earlier) — MDM/kiosk/remote-support over Ziti.

**PAM wave (v1.26.0–v1.27.0):**
- RDM-parity connection manager (folders/entries/grants/favorites/session
  ledger, org-scoped RLS, migration v81) with brokered *passwordless* launch.
- **Per-connection reach mode `direct` | `ziti`** (v82): guacd dials the target
  over the OpenZiti overlay — the target has *zero inbound exposure*.
- Dedicated dual Guacamole brokers (compose + Helm), per-user broker
  identities (no admin token in the browser), true read-only live monitoring,
  real client IP recorded.

**Ops wave (the 2026-07-14 system-design-review roadmap, items 1–9 executed):**
- Automated Postgres backups + **tested restore**; reboot-safe boot order;
  secret files owner-only; `orgscope` (RLS linter) now a **merge-blocking CI
  gate**; OPA decision cache + circuit breakers + tight timeouts on the hot
  path; Prometheus/SLO/tracing stack shipped; DB pools right-sized;
  **gateway-service retired — APISIX is the sole edge**; audit→ES reconcile +
  webhook lost-nudge recovery (transactional-outbox phase A); **KEK keyring
  (encv2)** so the master encryption key rotates without a flag-day + `cmd/rekey`
  to retire an exposed KEK.

### 2.2 Scale and maturity snapshot (code-measured)

- **~284,000 lines of Go** across 788 files; **324 test files / 2,673 test
  functions**; race-enabled sharded CI, real integration suite (OAuth, MFA,
  step-up, vault, rotation, Guacamole injection, JIT, cross-org), benchmarks,
  CodeQL + govulncheck, 12 GitHub Actions workflows.
- **194 admin-console pages**, each with a co-located test; end-user portal
  (My Access / My Devices / My Privileged Access / app launcher) included.
- **Ziti integration is application code, not config**: `sdk-golang v1.7.0`
  embedded (live `ziti.Context`, service bind/host), controller management API
  driven across 19 endpoint families, desired-state reconciler, user→identity
  sync, BrowZer clientless path **verified end-to-end in a real browser**.
- **Multi-tenancy enforced twice**: app-layer org context + Postgres **FORCE
  row-level security** stamped at pool checkout, with a custom static analyzer
  (`tools/orgscope`) failing the build on any unscoped tenant-table query.
- **Audit**: HMAC-SHA256 hash-chained events (tamper-evident), ES streaming
  with reconcile, compliance report generators (SOC 2 / ISO / GDPR surfaces),
  ISPM + IBDR (identity breach detection & response) modules.

### 2.3 Pillar scorecard (July 21)

| Pillar | July 10 verdict | July 21 verdict | What moved it |
|---|---|---|---|
| **IAM core (IdP/MFA/SCIM)** | Strongest pillar, delivery + HA failures | **GA-grade with caveats** | Step-up + multi-factor challenge + key rotation + SCIM filter fixed; caveats below |
| **IGA** | Real plumbing, broken enforcement | **Near-GA** | SoD fail-closed, enforced revocation, reviewer resolution, org-scoped campaigns, escalation worker |
| **PAM** | Genuinely mature, modern-PAM frontier missing | **GA-grade** | RDM-parity manager, per-user brokers, Ziti reach mode, live monitoring; frontier gaps remain (§7) |
| **ZTNA / Ziti** | Most mature pillar + biggest strategic opening | **GA-grade orchestration** | Kill switch, device correlation, agent enrollment hardening; event ingestion + per-org overlay still open |
| **Risk / ITDR** | Wired core + five dead engines | **MVP+** | Engines consolidated (purge), anomaly detection wired; SSF/CAEP + token-theft detection still open |
| **Platform / ops** | Ahead of docs; two headline defects | **GA-grade** | API keys fixed, org console fixed, backups/observability/KEK rotation/single-edge landed |
| **Clients** | "No companion app" cross-cutting gap | **Windows GA-ish; mobile MVP** | Signed Windows agent + Expo app phases 1–3; iOS/Android store-grade polish outstanding |

### 2.4 What still isn't true (verified remaining landmines)

These survived the sweep — each is a first-demo or first-POC risk and appears
in the refreshed gap register (§7) with a recommendation:

1. **Push MFA delivery still targets Google's decommissioned legacy FCM
   endpoint** (`internal/identity/pushmfa.go:547`) and unauthenticated APNS —
   the mobile app now renders push approvals, but the server can't deliver
   them. *One of the last "advertised but broken" items.*
2. **Magic-link email is still not sent** — the flow builds the link and rate
   limits, but no call into `internal/email` exists in
   `handlers_passwordless.go`.
3. **SAML IdP signing is still hand-rolled** — no `goxmldsig`/`crewjam`
   dependency; no XML canonicalization; inbound assertion signatures not
   verified. SAML SP schema drift was fixed (v83), but the crypto core is
   not standards-credible yet.
4. **No OAuth consent screen** — `require_consent` is not enforced anywhere in
   the live authorize path.
5. **Token Exchange (RFC 8693), DCR (RFC 7591), SSF/CAEP — absent** — the
   token endpoint serves exactly `authorization_code` / `refresh_token` /
   `client_credentials`. The agent-identity and CAE differentiators have no
   substrate yet.
6. **Outbound SCIM client — absent** — OpenIDX can be provisioned *into*, but
   cannot provision *out to* SaaS apps. The single biggest workforce-IAM
   functional gap vs Okta/Entra.
7. **HR-driven JML — absent** (no Workday/BambooHR/SuccessFactors source).
8. **SIEM forwarder (CEF/syslog/HEC) — absent** despite the unified audit
   store being GA-grade.
9. **EDR/MDM posture ingestion — absent** (CrowdStrike/Intune/Jamf).
10. **Ziti fabric events not ingested** into the unified audit pipeline — the
    network pillar is invisible in the SIEM/compliance story.
11. **A mock session helper ships in `internal/oauth/authorize_flow.go:291`**
    (`user-123` hardcoded) — audit says likely unrouted; delete or gate it
    before any pentest.
12. **Voice-call MFA is a stub** (mock Twilio SID).
13. **README still says "Single-tenant by design"** while the platform enforces
    FORCE-RLS multi-tenancy with a CI linter — the repo's front page
    contradicts one of its best engineering facts.
14. **No importers** from Okta/Auth0/Keycloak/AD (users/apps/policies), no
    published benchmarks, no i18n, no SBOM/signed server artifacts, and no
    third-party security attestation (SOC 2 / pentest) — the commercialization
    blockers, not engineering ones (§7.1).

**Bottom line:** the platform crossed the line from *"impressive demo with
landmines"* to *"design-partner-ready product"* in eleven days of focused
work. The remaining risk is concentrated in (a) four auth-delivery/standards
edges (push, magic link, SAML crypto, consent), (b) the outbound-provisioning
hole, and (c) commercialization scaffolding that has nothing to do with code.

---

## 3. The product thesis: set the features over Ziti

### 3.1 Why Ziti-first is the moat

Every identity vendor is bolting *network* onto *identity* (Okta ⇄ ZTNA
partners, Entra Global Secure Access, Zscaler buying identity signals), and
every network vendor is bolting *identity* onto *network* (Tailscale/NetBird
adding SCIM, ZTNA vendors adding posture). OpenIDX starts from the position
they are all converging toward: **the IdP, the policy engine, the PAM broker,
and the overlay network are one codebase over one database.**

The OpenZiti layer is what makes each pillar's promise *physical*:

| Pillar promise | Without Ziti | Over Ziti (OpenIDX today) |
|---|---|---|
| "Deprovisioned means gone" | Tokens expire eventually; VPN session lingers | Ziti identity deleted → live circuits severed ≤30 s (`ziti_user_sync.go` sweep) |
| "Least privilege" | App-level RBAC only | Per-service dial policies; the app is *dark* — no inbound port exists |
| "Privileged session security" | Jump host with standing creds | `reach_mode=ziti`: guacd dials over the overlay; target has zero inbound exposure; credential injected server-side (v82) |
| "Device trust" | UA sniffing / MDM tax | Enrolled agent posture checks bound to service policies; IAM trust ⇄ Ziti compliance correlated per device (v80) |
| "Kill switch" | Revoke token, hope apps re-check | Token + session + **network circuit** severed in one action (`kill_switch.go`) |
| "Clientless access" | VPN portal / RDP gateway | BrowZer: unmodified browser becomes a Ziti endpoint via injected runtime (verified e2e) |

No OSS competitor has this stack: **Keycloak/Zitadel/Authentik stop at the
IdP** (no network plane, no PAM). **NetBird/Tailscale/Twingate/Firezone have
the network** but a thin identity layer and no governance/PAM.
**OpenZiti itself has the fabric but no identity-governance control plane** —
the multi-tenant console, SCIM lifecycle, JIT, and metering are exactly what
NetFoundry monetizes commercially. OpenIDX is positioned to be **the open
control plane of the OpenZiti ecosystem** — the thing the ecosystem
conspicuously lacks — while ALSO being a standalone IAM/IGA/PAM.

### 3.2 What already sits over Ziti (shipped)

1. **Identity mirror** — every OpenIDX user auto-mirrored to a Ziti identity
   (`externalId` = user UUID → OIDC `sub`), groups → role attributes, device
   trust → `#device-trusted` (30 s poller + reconciler).
2. **One-click publishing** — per-route toggles create the Ziti service, bind
   + dial policies, and hosting; desired-state reconciler converges
   controller state from Postgres.
3. **BrowZer clientless** — OpenIDX is the OIDC issuer BrowZer trusts; login
   once, reach dark web apps from an unmodified browser (WSS last mile
   verified end-to-end).
4. **Agent fleet** — Windows (signed, self-updating), Android (MDM/kiosk),
   mobile scaffold; enrollment minted by OpenIDX, posture checks enforced in
   the proxy path.
5. **PAM over the overlay** — brokered SSH/RDP/VNC sessions whose *broker*
   dials the target through Ziti (`reach_mode=ziti`), so privileged targets
   are dark; recordings encrypted, legal holds honored.
6. **Cross-pillar enforcement** — kill switch and lifecycle sweeps that treat
   the network as an enforcement plane, not a separate product.

### 3.3 The "features over Ziti" build order

Priorities chosen for *sales impact per engineering week*, given §2's state:

**Wave A — make the network pillar auditable and tenant-clean (unblocks GTM):**

| # | Feature over Ziti | Why now | Effort |
|---|---|---|---|
| A1 | **Fabric event ingestion** — subscribe to controller circuit/session/posture events, normalize into `unified_audit_events`, index to ES | Completes "one audit trail" — today the network pillar is invisible to SIEM/compliance; also the substrate for metering (A4) and DEM | M |
| A2 | **Per-org overlay scoping** — remove the hardcoded fallback org, namespace Ziti attributes/service names per org, org-RBAC on Ziti passthrough | THE "OSS NetFoundry console" unlock; prerequisite for MSP channel and any multi-tenant SaaS offer | L |
| A3 | **Continuous posture → mid-session revocation** on the tunneler path (posture degrade → delete API sessions via mgmt API) | Turns posture from gate to guarantee; demo: yank disk-encryption → circuit dies live | M |
| A4 | **Usage metering per org/service/identity** from A1's event stream + consumption dashboard | NetFoundry-parity feature; the MSP billing substrate | M |

**Wave B — governance reaches the network (the demo that closes deals, §4):**

| # | Feature over Ziti | Why | Effort |
|---|---|---|---|
| B1 | **JIT network grants** — access-request approval adds a time-bound role attribute to the target service policy; expiry sweeper removes it and kills sessions | "Approve → network exists for 8 h → vanishes" is the single most differentiated demo vs SailPoint+Zscaler stacks | M |
| B2 | **Certification-revoke → policy detach** — extend the enforced-revocation executor to remove Ziti dial attributes and sever circuits | Completes decision-to-packet within the existing campaign engine | S–M |
| B3 | **Step-up on posture/risk change in the access path** — proxy 302s to OAuth with `acr_values=mfa` | The step-up verifier now actually verifies (WS-01), so this is safe to build | M |

**Wave C — modern-PAM and workload features on the fabric:**

| # | Feature over Ziti | Why | Effort |
|---|---|---|---|
| C1 | **`openidx connect` native-client access** — approved session mints a short-lived scoped Ziti identity; local listener lets unmodified `ssh`/`psql`/`kubectl` reach dark targets | Teleport/StrongDM-class UX at zero marginal license cost; reuses JIT + enrollment machinery | L |
| C2 | **Secretless injection at the edge** — vault secret resolved at connect time and injected at the tunneler; client never sees it | Aembit/Conjur-class with no new agent | L |
| C3 | **Workload identity federation** — CI OIDC token (GitHub/GitLab) → ephemeral scoped Ziti identity, TTL-swept | NHI story on the fabric; pairs with RFC 8693 work | M |
| C4 | **EDR/MDM signal ingestion** (CrowdStrike ZTA / Intune compliance) into posture evaluation | Table stakes in enterprise ZTNA evals | M |

**Wave D — the frontier (agents) once RFC 8693 + DCR land:**

| # | Feature over Ziti | Why | Effort |
|---|---|---|---|
| D1 | **MCP / AI-agent gateway** — each agent a Ziti identity; MCP servers published as dark services; per-tool OPA allowlists; every call audited | The 2026 battleground; OpenIDX can do *network-enforced* agent containment, which pure-IdP rivals cannot | L |
| D2 | **SSF/CAEP transmitter + receiver** with Ziti termination as the receiver's actuator | First OSS SSF/CAEP **with native network termination** — the headline capability (§4.4) | L |
| D3 | **K8s fabric subchart + HA controller (Raft) + Terraform provider** | Production posture for platform buyers | L |

Deliberately **not** on the list: SWG/CASB/DLP inline inspection, IoT/OT
discovery, global PoP networks — that is SSE-vendor territory where OpenIDX
cannot win on breadth; consolidation checkboxes only (DNS filtering profile
later).

---

## 4. Governance is the control plane: how it affects IAM, Ziti, and PAM

The question "how does governance affect IAM / Ziti / PAM" has a precise
architectural answer in OpenIDX, and it is the core of the sales story.

### 4.1 The model

**Governance is the decision layer; IAM, PAM, and Ziti are enforcement
planes.** Because all four share one Postgres and one event/sweep fabric, a
governance decision propagates as *writes and reconciles measured in seconds*,
not as connector tickets measured in days:

```
                       ┌───────────────────────────────┐
                       │         GOVERNANCE            │
                       │  access requests + approvals  │
                       │  SoD policies (fail-closed)   │
                       │  certification campaigns      │
                       │  JIT elevation + expiry       │
                       │  lifecycle policies           │
                       └──────┬────────┬────────┬──────┘
                    decides   │        │        │
              ┌───────────────┘        │        └───────────────┐
              ▼                        ▼                        ▼
        ┌──────────┐             ┌──────────┐             ┌──────────┐
        │   IAM    │             │   PAM    │             │   Ziti   │
        │ roles    │             │ vault    │             │ identity │
        │ groups   │             │ grants   │             │ attrs    │
        │ sessions │             │ checkout │             │ policies │
        │ tokens   │             │ sessions │             │ circuits │
        └────┬─────┘             └────┬─────┘             └────┬─────┘
             │      enforcement:      │                        │
             │  session revocation    │  checkout revoke       │  circuit
             │  API-key revoke        │  Guacamole terminate   │  severance
             │  step-up require       │  JIT expiry            │  policy detach
             └────────────┬───────────┴────────────┬───────────┘
                          ▼                        ▼
                 unified_audit_events      kill switch (all pillars, 1 action)
                 (HMAC hash-chained)
```

### 4.2 Governance → IAM (live today)

- **Access request → approval → grant**: multi-step approval chains (per-step
  approvers, fail-closed auto-approve conditions) fulfill role/group/app
  grants inside the same transaction fabric the IdP reads at token issuance.
- **SoD is preventive and fail-closed** at *both* direct role grant and
  request fulfillment (v1.25.0): a conflicting grant is refused, not logged.
- **Certification revoke now revokes**: the grant is deleted *and* live
  sessions are killed — an access review is an enforcement action, not a
  report.
- **JIT elevation** expires by sweeper: elevated roles *and* application
  access disappear on schedule.
- **Lifecycle**: joiner/mover/leaver events (API, SCIM, directory sync)
  propagate through `deprovisionUser` inline plus ≤30 s reconcile sweeps.
- *Still open:* per-app conditional access at issuance, dynamic groups,
  event-driven JML from an HR source (§7).

### 4.3 Governance → PAM (live today)

- **Vault access rides the same request pipeline**: credential checkout can
  require approval; grants are principal-keyed (user | role) so certifying a
  *role* certifies its vault reach.
- **JIT checkout**: time-bound credential leases with one-shot retrieve,
  early return, and sweeper-enforced expiry — revoking the elevation revokes
  the credential.
- **Session policy flags per connection** (`require_approval`, `record_session`,
  `allow_reveal`) enforced at the broker; single-use approvals for session
  launch; recordings encrypted with rotating keys and legal holds.
- **Deprovision/kill switch terminates live privileged sessions** — the only
  place in the market where an access review and a live RDP session share a
  database.
- *Still open:* break-glass accounts, dual-control/exclusivity on checkout,
  ticketing enforcement, privileged-account discovery (§7).

### 4.4 Governance → Ziti (the differentiator — half live, half next)

Live today:
- **Identity-level**: user disabled/deleted (by decision, sweep, or kill
  switch) → Ziti identity deleted → live circuits die. Device-level revoke
  severs one machine across IAM + Ziti.
- **Group/role attributes flow to dial policies** via the sync poller, so
  role revocation already narrows network reach on the next reconcile.
- **Posture policy** gates the proxied request path fail-closed.

Next (Wave B, §3.3): **JIT network grants** (approval → time-bound dial
attribute → sweeper removes + kills sessions) and **certification-revoke →
policy detach**. With those two wires, the claim becomes literal:

> **"A revoke decision doesn't open a ticket. It deletes the grant, kills the
> session, terminates the privileged connection, and severs the network
> circuit — in under 30 seconds, with one hash-chained audit trail."**

SailPoint + CyberArk + Zscaler need three products, two connectors, and a
services engagement to approximate that sentence. It is OpenIDX's whole
architecture speaking. This — not feature-count parity — is what to sell.

### 4.5 What governance still cannot see (honest limits)

- **Third-party app entitlements** — without outbound SCIM + an entitlement
  warehouse, governance governs *OpenIDX-managed* access (incl. network and
  vault), not entitlements living inside Salesforce/GitHub/AWS. This is the
  most consequential IGA gap for mid-market deals (§7).
- **The network pillar's events** — until fabric event ingestion (Wave A1)
  lands, circuit history can't be attached to campaign evidence.
- **HR truth** — joiner/mover/leaver still originates from directory sync or
  API, not the HR system of record.

---

## 5. Market re-analysis (July 2026)

Fresh research, 2026-07-21. Figures are directional composites of multiple
analyst estimates; sources by domain.

### 5.1 The four markets OpenIDX spans

| Segment | 2026 size | Growth | Note |
|---|---|---|---|
| **IAM (overall)** | ~$24–30B | 11–15% CAGR | Gartner pegs end-user IAM spend at $24.1B in 2026 (gartner.com) |
| **IGA** | ~$8–11B | 14–16% CAGR | Financial sector ≈35% of revenue (grandviewresearch.com) |
| **PAM** | ~$4.4–6.6B | **21–24% CAGR** | The fastest-growing core identity segment (marketsandmarkets.com, fortunebusinessinsights.com) |
| **ZTNA (pure-play)** | ~$1.3–2.5B | ~25% CAGR | >70% of new remote-access deployments now choose ZTNA over VPN (Gartner via uinat.com); SASE superset >$13B (delloro.com) |
| **NHI / machine identity** | ~$8–21B (definitions vary) | very high | Machine:human identity ratio now **109:1**, up from 82:1 in one year (paloaltonetworks.com); only 5.7% of orgs have full service-account visibility |
| **AI-agent security** | ~$1.65B | **42% CAGR** → $13.5B by 2032 | Gartner: 40% of enterprise apps embed task agents by end-2026; 25% of breaches traced to AI-agent abuse by 2028 |

The combined addressable surface for a unified platform is $40B+ and every
sub-segment is growing double digits — but the strategically important fact is
not size, it's **convergence**.

### 5.2 The consolidation wave validates the unified thesis

In twelve months, every major platform vendor bought its way toward exactly
the architecture OpenIDX already has in one codebase:

- **Palo Alto Networks × CyberArk — $25B, closed 2026-02-11.** Identity is
  now PANW's fourth platform pillar (cyberark.com).
- **Delinea × StrongDM** (announced 2026-01-15) — "runtime authorization for
  the agentic-AI era" (delinea.com).
- **Okta × Axiom Security** (closed 2025-09) — the IdP leader buying PAM
  (sdxcentral.com); Okta's "Identity Security Fabric" spans workforce,
  customer, and AI-agent identity; Cross App Access (XAA) has 25+ adopters.
- **CrowdStrike × SGNL ($627.9M, 2026-01)**, **Cisco × Astrix (~$400M)**,
  **Zscaler × Red Canary/SquareX/SPLX + Symmetry** — EDR/SSE vendors buying
  identity and NHI startups (bankinfosecurity.com, calcalistech.com).
- Buyer side: **76% of organizations are actively consolidating identity
  tooling**; 91% rank identity a top-5 priority; the typical enterprise runs
  5–10 non-integrated identity systems (helpnetsecurity.com, Jan 2026).

**Implication:** "one platform from IdP to network packet" is no longer a
contrarian architecture — it is the stated direction of every incumbent. They
are assembling it by M&A over 3–5 integration years; OpenIDX has it as a
single Postgres today. The window where "actually unified" is a demoable
differentiator is now, before the incumbents finish stitching.

### 5.3 The pricing revolt is the wedge

List-price reality for the stack OpenIDX replaces (per user/month):

| Stack element | Vendor list price |
|---|---|
| SSO+MFA+lifecycle+governance | Okta Essentials $17; à la carte $18–25; **Okta Identity Governance alone $9–15** |
| Microsoft route | Entra P2 $9 + Governance $7, or Entra Suite $12; **M365 E7 $99** (with Agent 365 + Copilot) |
| MFA/device trust | Duo $3–9 |
| PAM | CyberArk ≈$2.4–12K *per privileged user per year*, quote-only; Delinea $12–18/account/mo; Teleport median contract **$90K/yr**, $24–40 per resource/mo |
| ZTNA | Zscaler ZPA $6–10+ (quiet +35% hikes Aug 2025); Cloudflare $7; Tailscale $8–18; Twingate $10 |

A **500-employee company realistically pays $200K–$400K+/year (≈$33–65 per
user per month)** for the stacked capability set, before implementation
services and renewal uplifts (composite: costbench.com, vendr.com,
underdefense.com, npifinancial.com). And the trend is *worse* for buyers:
Microsoft raised M365 list prices up to 43% on 2026-07-01 and removed EA
volume discounts; Auth0 customers report 3–4× renewal quotes; Zscaler raised
SKUs 35%+ without announcement; Teleport restricted its Community Edition to
companies under 100 employees / $10M revenue (github.com/gravitational).

**OpenIDX's structural attack:** flat infrastructure cost, no per-identity
metering — which matters double when machine identities outnumber humans
109:1 and AI agents multiply principals further. The honest counter-position
is not "free Okta"; it is *"the consolidation the market is demanding, at
infrastructure cost, on your own hardware."*

### 5.4 Sovereignty is a paying tailwind, not a slogan

- Microsoft testified to the French Senate (June 2025) that it **cannot
  guarantee** EU-hosted data is beyond US CLOUD Act reach (databalance.eu).
- The EU **Cloud and AI Development Act** proposal (adopted 2026-06-03)
  creates a four-tier cloud-sovereignty framework for public procurement
  (techtimes.com). Gartner: sovereign-cloud IaaS spend hits **$80B in 2026,
  Europe growing 83%** (gartner.com).
- **NIS2**: first compliance audits due 2026-06-30, obligations culminating
  October 2026 — explicitly requiring MFA/continuous authentication, with
  personal liability for management (compliancehub.wiki). **DORA** entered
  its first real enforcement cycle for financial entities in 2026.
  **eIDAS 2.0**: every member state must offer an EUDI wallet by end-2026;
  regulated sectors must accept them by Nov 2027.
- Self-hosted identity is explicitly benefiting: EU hosting providers
  describe self-managed Keycloak as "the baseline" for critical-infrastructure
  identity (blog.elest.io); the EU Open Source Strategy promotes European
  open alternatives.

A self-hostable, Apache-2.0, all-four-pillars platform is aimed at the
center of this demand. No US-SaaS incumbent can follow it there.

### 5.5 The threat landscape sells exactly what OpenIDX does

- **Credential abuse appears in 39% of all breaches** — the most pervasive
  technique (Verizon DBIR 2026); **67% of incidents started with identity**
  (Sophos 2026); token theft accounts for 31% of M365-environment breaches.
- **Helpdesk social engineering** (Scattered Spider): M&S ~£300M operating
  hit, Co-op ~£120M, Clorox suing Cognizant for $380M over a password reset
  given out by phone. Sells: phishing-resistant MFA, step-up, identity
  verification at reset.
- **OAuth/token abuse at SaaS scale**: Salesloft Drift tokens → mass data
  theft from 700+ orgs incl. Cloudflare, PANW, Zscaler; ShinyHunters
  Salesforce campaigns claimed ~1B records. Sells: token lifecycle control,
  consent governance, session revocation, CAE.
- **NHI compromise**: the Shai-Hulud npm worm exposed 33,185 secrets (3,760
  still valid days later); BeyondTrust's API key → US Treasury. Sells: NHI
  inventory, rotation, short-lived credentials — and *network* containment
  when secrets leak (a dark service is unreachable even with a stolen token
  if the caller has no overlay identity).
- **VPN CVE fatigue** (Ivanti/Fortinet/GlobalProtect exploit waves) keeps
  pushing the >70% ZTNA-over-VPN adoption number up.

Every one of these maps to a shipped OpenIDX capability or a Wave A–B item
(§3.3) — this is the demand-side narrative for content marketing and POC
scoping.

---

## 6. Competitive position

### 6.1 The OpenZiti ecosystem opening (verified July 2026)

The July 10 register called the OSS OpenZiti management plane "the biggest
strategic opening in the whole product." Fresh research confirms it is still
open — and *wider*:

- **OpenZiti v2.0.0 GA'd 2026-05-20** (v2.0.1 on 2026-07-15): Raft-based
  **controller HA is GA**, JWT/OIDC default auth, a "dark management plane,"
  and a **beta fine-grained admin-permissions model** — i.e., upstream just
  removed the HA blocker and shipped the delegation primitives a multi-tenant
  console needs (blog.openziti.io). *Action: plan the SDK/controller bump; v2
  routers require v2 controllers.*
- **The OSS console is vestigial**: ZAC has **37 GitHub stars** vs 4,302 for
  the core repo. Monitoring, PKI automation, SCIM lifecycle, Terraform
  provider, multi-tenancy, and SLAs exist **only in NetFoundry's commercial
  tier**, which is now **quote-only** (the free Teams tier is gone) and
  explicitly frames OSS OpenZiti as for *"home use, non-production use cases
  and learning"* (netfoundry.io).
- **Precedent that open control planes win mindshare**: Headscale — the
  community OSS control server for Tailscale — has **41,940 stars, more than
  Tailscale's own repo**. NetBird (fully-OSS control plane, MSP-first) hit
  27.5k stars and a **$10M Series A (Jan 2026)**.
- **NetFoundry validated the up-stack demand** ($15M+ Series A incl. Cisco
  Investments; Frontdoor ingress, zLAN OT segmentation, and enterprise
  **MCP/LLM gateways** launched Nov 2025–Jun 2026, with an OSS
  `openziti/llm-gateway` seed repo).

**The whitespace nobody serves:** a *self-hosted, multi-tenant, white-label*
control plane on an app-embedded dark-service fabric, fused with IAM +
governance + PAM. NetBird is closest but has no IGA/PAM depth; Defguard
attempts IAM+VPN at a fraction of the depth; Tailscale (~40k paying
customers, $1.45B valuation) *still has no MSP portal*. OpenIDX with per-org
overlay scoping (Wave A2) is the only credible claimant.

**Honest risks in the Ziti bet** (from the same research): OpenZiti's
community is small (~4.3k stars, ~84 active forum users/month) and
single-vendor governed — docs now 301-redirect to netfoundry.io; NetFoundry
is moving up-stack fast and could occupy adjacent value; WireGuard-mesh
rivals carry 6–10× the mindshare. Mitigations in §10.

### 6.2 Battle lines by segment

| Against | Their strength | OpenIDX wins when… | Avoid when… |
|---|---|---|---|
| **Okta / Entra** (workforce IAM) | Ecosystem breadth (7k+ integrations), brand, agent-identity momentum (XAA, Agent 365 $15/u/mo) | Buyer wants self-hosted/sovereign, hates SKU stacking ($18–65/u/mo stacked), needs IAM+PAM+network in one; EU/NIS2/DORA-driven | Buyer is all-in M365 E5/E7 (marginal Entra cost ≈ $0); needs deep SaaS-app provisioning *today* (outbound SCIM gap) |
| **Keycloak / Zitadel / Authentik** (OSS IdP) | Mature IdP cores, big communities, certified OIDC | Deal needs more than an IdP: governance, PAM sessions, network access, one audit trail. "Keycloak is an IdP; OpenIDX is Okta+SailPoint+CyberArk-shaped" | Buyer needs *only* SSO and picks the largest community; OIDC-certification checkbox required (we're uncertified) |
| **SailPoint / Saviynt** (IGA) | Connector/SoD depth, auditor familiarity, agentic copilots | Mid-market wants governance *with enforcement* (revoke = session+circuit kill) at flat cost; greenfield IGA where $9–15/u/mo Okta-IGA or SailPoint quotes sting | Fortune-500 IGA RFP with ERP SoD depth and 250+ entitlement connectors — we lose the connector row outright |
| **CyberArk-PANW / Delinea / Teleport / StrongDM** (PAM) | Vault pedigree, 300+ rotators, ephemeral-cert UX (Teleport) | Buyer needs brokered+recorded+dark privileged access fused with IdP+governance; Teleport's $90K median contract or per-resource metering hurts; CE license restrictions push OSS-first shops our way | Windows-heavy PEDM estates; DB/K8s protocol-aware proxying as hard requirement (roadmap C1) |
| **Zscaler / Cloudflare / Tailscale / Twingate / NetBird** (ZTNA) | PoP networks, inline inspection (SSE), WireGuard simplicity, mindshare | App-embedded dark services + clientless BrowZer + PAM-over-overlay + governance in one; MSP white-label multi-tenant (nobody OSS serves it); sovereignty (self-hosted fabric, no vendor cloud in the data path) | Buyer wants SWG/CASB/DLP inline inspection (SSE) or a global PoP backbone — different product; pure mesh-VPN simplicity buyers (NetBird/Tailscale are easier day-1) |
| **NetFoundry** (same fabric) | Hosted control plane, PKI automation, SLAs, enterprise logos, Cisco backing | Buyer must self-host (sovereignty/air-gap), wants IAM/IGA/PAM fused, or is an MSP needing white-label multi-tenant (NetFoundry Partner tier is quote-only OEM) | Buyer wants SaaS-managed fabric with 99.995% SLA and zero ops — concede or partner |

### 6.3 The one-sentence positioning

> **"OpenIDX is the open, self-hosted identity-security platform where the
> IdP, governance, privileged access, and the zero-trust network are one
> system — so a single decision (approve, revoke, kill) is enforced from the
> token to the packet in seconds, at flat infrastructure cost."**

Supporting proof points to lead demos with (all shipped):
1. **The kill switch** — one action severs sessions, API keys, vault
   checkouts, live RDP/SSH sessions, and network circuits (`kill_switch.go`).
2. **Access 360** — one screen answering "what can this human reach, across
   app, vault, and network" — the auditor's dream artifact.
3. **Dark privileged access** — a recorded RDP session to a target with *no
   inbound port*, credential injected server-side, over the overlay
   (`reach_mode=ziti`).
4. **Clientless day-1** — BrowZer: publish an internal app to a contractor's
   unmodified browser in minutes, with posture policy.
5. **The RLS belt** — FORCE row-level security with a merge-blocking CI
   linter: multi-tenancy that survives a pentest, provable in the repo.

---

## 7. The refreshed gap register

The July 10 register remains the exhaustive per-pillar backlog. This section
is the *commercially re-prioritized* view: what actually blocks selling, in
order, as of 2026-07-21.

### 7.1 Deal-blockers (commercial scaffolding, not features)

These block revenue regardless of feature state. None is engineering-hard;
all are calendar-bound — start them **now, in parallel** with Wave A.

| # | Blocker | Why it blocks | Move |
|---|---|---|---|
| D1 | **No third-party security attestation** — no SOC 2, no published pentest | The first vendor-security questionnaire stalls the deal; even self-host buyers ask for the *vendor's* posture | Commission a reputable pentest on v1.27+ now (fast, ~weeks); start SOC 2 Type II clock (§8.6 for cost/timeline) |
| D2 | **Repo front page contradicts the product** — README says "single-tenant by design"; stale docs; `.team/` artifacts; mock helper in `authorize_flow.go` | OSS buyers read the repo before the demo; contradictions read as unreliability | One hygiene PR: rewrite README (multi-tenant + RLS belt as a *headline*), delete stale docs/dead helpers, add SECURITY.md accuracy pass |
| D3 | **No published deployment story for evaluators** — compose exists, but no "one command, 15 minutes to a working login + published app" quickstart with real certs | Time-to-first-value is the OSS funnel's conversion gate; NetBird/Tailscale onboard in minutes | A `quickstart` profile (compose + bundled Ziti + seeded org + Let's Encrypt) + a 10-minute video; measure TTFV |
| D4 | **No importers** (Okta/Auth0/Keycloak/AD users, groups, apps) | Displacement deals die at migration cost; Auth0's 3–4× renewal hikes are sending refugees *now* | Keycloak realm-export importer first (same OSS buyer), then Okta/Auth0 API importers |
| D5 | **Licensing/commercial boundary undefined** | Procurement can't buy "a repo"; OEM/MSP partners can't sign without terms | Publish the open-core boundary + a commercial license & support offering (§8.3) |
| D6 | **No published benchmarks or reference architecture** | "Will it hold 10k users?" has no answer; single-Postgres ceiling unknown | Publish a reproducible load-test (auth RPS, SCIM throughput, overlay session scale) on a documented reference box |
| D7 | **Supply-chain posture incomplete for a security vendor** — Windows client is signed, but server images lack SBOM/cosign/SLSA provenance | Buyers now audit vendor supply chain post-xz/Shai-Hulud | Add SBOM + cosign signing to `docker.yml`/`release.yml`; publish a SECURITY-SUPPLY-CHAIN.md |
| D8 | **No i18n** (all-English console) | Blocks the sovereignty segments the product is aimed at (EU, Türkiye) | `react-i18next` pass on auth-critical surfaces first (login, MFA, portal) |

### 7.2 Product gaps that lose deals (re-verified, priority order)

**Tier 1 — first-demo/POC landmines (fix before any external evaluation):**

| Gap | Evidence | Effort |
|---|---|---|
| Push MFA delivery hits Google's dead legacy FCM endpoint + unauthenticated APNS | `internal/identity/pushmfa.go:547` | M (FCM HTTP v1 + APNS token auth; mobile app already renders approvals) |
| Magic-link email never sent | no email call in `handlers_passwordless.go` | S (template + `SendAsync` wire) |
| SAML IdP crypto hand-rolled (no canonicalization, inbound sigs unverified) | no `goxmldsig` in `go.mod` | M (adopt `russellhaering/goxmldsig`, real X.509 at first boot, verify inbound) |
| No OAuth consent screen | `require_consent` unenforced | S–M (consent step gated per app) |
| Mock session helper in tree | `internal/oauth/authorize_flow.go:291` (`user-123`) | S (delete or build-tag it out; confirm unrouted) |
| Voice-call MFA stubbed | mock Twilio SID | S (finish or remove from UI) |

**Tier 2 — capability gaps that decide evals (sequence with §3.3 waves):**

| Gap | Deal type it loses | Effort |
|---|---|---|
| **Outbound SCIM client** (provision *into* SaaS) | Any workforce-IAM displacement vs Okta/Entra | L — the single highest-leverage build; unlocks IGA fulfillment + deprovision automation too |
| **HR-driven JML** (Workday/BambooHR/SuccessFactors source) | Mid-market lifecycle deals ("where does the joiner come from?") | L (model as directory-connector type) |
| **Ziti fabric event ingestion → unified audit/SIEM** (Wave A1) | Compliance-led ZTNA deals; completes the one-audit-trail story | M |
| **Per-org overlay scoping** (Wave A2) | The entire MSP channel + multi-tenant SaaS posture | L |
| **SIEM forwarder (CEF/syslog/HEC)** | Every enterprise scorecard row "streams to Splunk?" | S–M (worker over the existing outbox) |
| **EDR/MDM posture ingestion** (CrowdStrike ZTA/Intune) | Enterprise ZTNA bake-offs | M |
| **JIT network grants wired to governance** (Wave B1) | The differentiator demo (§4.4) | M |
| **Token Exchange (RFC 8693) + DCR (RFC 7591)** | Everything agent-identity; 2026's hottest RFP section | M each |
| **SSF/CAEP transmitter/receiver** (Wave D2) | "First OSS SSF/CAEP + network termination" headline; CAE RFP rows | L |
| **Break-glass + dual-control/exclusivity on checkout** | PAM evals vs CyberArk muscle memory | S–M each |
| **Detective SoD sweep + violation dashboard** | IGA compliance evals (preventive now works; auditors ask for detective) | M |
| **Privileged-account discovery** | PAM land-and-expand ("what don't I know about?") | L |
| **DB/K8s session brokering; SSH CA/ephemeral certs; `openidx connect`** (Wave C1) | Dev-platform PAM vs Teleport/StrongDM | L–XL |
| **Entitlement warehouse + orphan detection** | Upper-mid-market IGA | XL |
| **OIDC pairwise subjects; complete SAML SLO; DB-backed feature flags** | Standards-hygiene rows | S each |

**Explicitly deprioritized (do not build now):** ERP-depth SoD, PEDM,
SWG/CASB/DLP, IoT/OT discovery, global PoPs. **Timed watch item:** eIDAS
2.0 — every member state must offer an EUDI wallet by end-2026 and regulated
relying parties (banks, telecom, health, energy) must *accept* wallet
credentials by ~Dec 2027; plan OpenID4VP relying-party (wallet-verification)
support for H2 2027 so sovereign-segment RFPs can be answered "roadmap,
dated" — wallet *issuance* stays out of scope.

### 7.3 Closed since 2026-07-10

Fourteen of the July 10 register's P0 rows are verified closed in code —
see §2.1. Update `MARKET_GAP_ANALYSIS_2026.md` statuses accordingly (or mark
it superseded-in-part by this document) so the registers never contradict.

### 7.4 Closed 2026-07-24 (this cycle)

Verified against current `main`:

- **§7.2 Tier-1 landmines — all closed.** Push MFA is on FCM HTTP v1 (`oauth2/google`,
  `fcm.googleapis.com/v1/.../messages:send`); SAML uses `goxmldsig` (canonicalization +
  inbound signature verification); the OAuth consent screen is enforced
  (`internal/oauth/consent.go`); the `user-123` mock session helper is gone; voice-call
  MFA is a real Twilio provider. The two that were still open are now fixed:
  - **Magic-link token leak** (#566) — the routed `/identity/passwordless/magic-link`
    handler returned the one-time token in its JSON body and never emailed it; now it
    sends via `SendMagicLinkEmail` and never echoes the token (non-enumerating response).
  - **OIDC pairwise subjects advertised-but-not-implemented** (#567) — `generateSubject`
    returned the raw user id for every client despite discovery advertising `pairwise`;
    now a real per-client pairwise `sub` (HMAC) behind `OIDC_PAIRWISE_SUBJECTS`, plus a
    fix to `validateAccessToken` (it read the token as a Redis hash while the endpoint
    stores JSON, so UserInfo failed on real tokens).
- **§7.2 Tier-2 — the big builds are shipped:** Outbound SCIM (#543), HR-driven JML
  (#544), Token Exchange + DCR (#545), EDR/MDM posture (#546), SSF/CAEP (#547), A3/B2
  network termination (#549), B1 JIT grants (#551), A4 usage metering (#553), D1 MCP
  gateway (#555), **A2 per-org overlay scoping** (#563), **D3 K8s fabric + Terraform**
  (#564). SIEM forwarder (CEF/syslog/HEC) and complete SAML SLO already exist in-tree.

**Wave 2 — the §7.4 open list is now closed (2026-07-24), each a dedicated PR with tests:**
- **Break-glass + dual-control/exclusivity on PAM checkout** (#570) — opt-in per-entry
  flags: a two-person rule (a second admin authorizes the specific checkout,
  authorizer ≠ requester), one-holder-at-a-time exclusivity, and a loudly-audited
  emergency bypass. Migration v105.
- **Detective SoD sweep + violation register** (#571) — scans existing role/group
  assignments against `separation_of_duty` policies for toxic combinations that the
  preventive control never catches; self-reconciling, `waived` is sticky. Migration v106.
- **Privileged-account discovery** (#572) — sweeps the identity store for standing
  admin grants, privileged group membership, service-account patterns, and dormant
  privileged accounts; tracks each to onboarding. Migration v107.
- **Entitlement warehouse + orphan detection** (#573) — one "who has access to what"
  surface unioning every entitlement source, each row stamped time-bound and orphaned
  (owner disabled/missing). Migration v108.
- **DB/K8s session brokering + SSH CA (`openidx connect`)** (#574) — OpenIDX as an SSH
  certificate authority (per-org CA private key in the vault), minting short-lived,
  principal-scoped user certs; plus the brokered-session ledger for ssh/db/k8s.
  Migration v109.

Nothing from the §7.4 open list remains. Remaining roadmap items live in §7's forward
tables, not here.

---

## 8. Go-to-market: the way to sell

Benchmarked against 15+ commercial-OSS identity/security vendors (July 2026
research; sources by domain). The honest headline first: **plan revenue
around dozens of $10–60K contracts, not thousands of subscriptions.**
Org-level conversion of self-hosted OSS runs **0.2–1%** — Grafana had ~2,000
paying of ~1M using orgs ("90% of our users will never pay us, and that's by
design" — CEO Raj Dutt); Elastic ~1%; Confluent built $5B+ on <1% — an order
of magnitude below cloud-freemium's 9–18%. Growth after the first sale is
expansion-led (GitLab: 123% net retention). Zitadel had ~150 paying
customers on $15.5M raised; Infisical reached cash-flow-positive + a $16M
Series A on the same motion OpenIDX should run. The documented first-dollar
triggers for self-hosted security products, in order of evidence strength:
**(1) compliance-grade builds** (Teleport gates FIPS/FedRAMP to Enterprise;
Ubuntu Pro sells FIPS modules; Chainguard rode compliance artifacts from $5M
to $40M ARR in two years), **(2) audit/governance gating per the buyer-based
open-core canon** (IC features free, manager/executive features paid —
OCV/GitLab doctrine), **(3) managed-hosting ops relief** (Sentry: 70%
self-serve SaaS; Plausible/PostHog: 100% cloud revenue).

### 8.1 Who buys first (ICP, in order)

| # | Segment | Why they buy | Entry wedge |
|---|---|---|---|
| 1 | **Türkiye regulated & public sector** (banks/fintech under BDDK, public institutions) | **BDDK requires banks' primary AND secondary systems located in Türkiye**; multi-tenant public SaaS is effectively excluded for core banking — a cloud IdP cannot be the authoritative identity layer. Same localization pattern in capital markets (SPK), payments (TCMB), telecom (BTK), and public sector (Circular 2019/12: critical data + email in-country). KVKK's 2024 SCC regime (Board-approved clauses, 5-business-day notification) taxes every US-SaaS tenant. **Domestic software gets a mandatory 15% price advantage in public tenders** (yerli malı) | Self-hosted unified IAM+PAM with Turkish support + KVKK/BDDK compliance pack. Local PAM incumbent Kron (300+ customers, FY2024 revenue −29.6% amid subscription transition, ~$10–15M scale) is single-pillar — beatable on breadth. **The real competitor is "free Keycloak + local SI"** (Akbank runs Keycloak; local Keycloak consultancies exist) — so the pitch is *supported, certified, CRA/DORA-mapped four-pillar suite*, never merely "open source" |
| 2 | **EU sovereignty mid-market (100–2,000 employees)**, DACH/Nordics/Benelux first | NIS2 audits from 2026-06-30 (Art 21(2)(i)/(j): access control + "MFA or continuous authentication"; fines to €10M/2%; personal liability). **DORA's RTS (Reg. 2024/1774, Arts 20–21) is effectively a PAM mandate**: unique identities, least privilege, privileged access on need-to-use basis, strong auth for privileged/remote access, access reviews every 6 months for critical functions. Microsoft's CLOUD-Act Senate testimony; EuroStack (~€300B framing); ICC/Microsoft incident; Danish/Schleswig-Holstein migrations; Gartner: EU sovereign-cloud spend +83% in 2026 | "Sovereign identity fabric": Bare.ID ("100% German supply chain") and Univention/openDesk prove buyers pay for the label — but they are Keycloak wrappers, and Evolveum midPoint is IGA-only; **none offers IAM+IGA+PAM+ZTNA as one suite** |
| 3 | **MSPs / MSSPs** | 94% of SMBs use an MSP; MSP zero-trust demand +150% since 2021; **no OSS vendor offers a self-hosted white-label multi-tenant ZTNA+IAM control plane** (NetBird is closest, no IGA/PAM; Tailscale has no MSP portal at all) | White-label multi-tenant console (RLS multi-tenancy is already built; per-org overlay = Wave A2) + per-active-user pricing, no minimums — the Duo/NetBird playbook |
| 4 | **OSS-first engineering orgs** (50–500 eng) | Auth0 3–4× renewal refugees; Teleport CE now restricted to <100 employees/<$10M; HashiCorp-BUSL distrust; VPN CVE fatigue | Keycloak/Auth0 importer + TCO calculator + `openidx connect` (Wave C1) for the Teleport-shaped need |

**Not the ICP (do not chase in year one):** Fortune-500 IGA RFPs (connector
count knockout), all-in M365 E5/E7 shops (marginal Entra cost ≈ $0), SSE
buyers wanting inline inspection, and anyone requiring a hosted multi-region
SaaS with 99.99% SLAs.

### 8.2 The motion: community-led, design-partner-anchored

1. **Fix time-to-first-value, then launch loudly.** The funnel is
   stars → Discord → production self-hosters → paying accounts. Infisical's
   open-sourcing + Reddit/Show-HN launch made it GitHub's fastest-growing
   repo of the day and carried it to 25k+ stars and enterprise logos;
   Authentik states most paying customers *already ran it* at home or as
   shadow IT. Prerequisites: the D3 quickstart (15-minute working login +
   published dark app), honest README (D2), and Tier-1 landmine fixes —
   *then* Show HN / r/selfhosted / r/opensource.
2. **Recruit 5–10 design partners** (free Enterprise features + roadmap
   influence, in exchange for logo/reference/case study): 2–3 Türkiye
   regulated, 2–3 EU mid-market, 1–2 MSPs, 1–2 OSS-first eng orgs.
   Sales-assisted POCs convert ~50% (ICONIQ 2026) — every POC gets
   white-glove help.
3. **Sell the seams, not the checklist.** The demo script is §6.3's five
   proof points, ending with the revoke-to-packet moment (§4.4). Against
   point products, always widen the frame to the stacked bill (§5.3).

### 8.3 Licensing and the open-core boundary

The 2023–2026 record is unambiguous: **backlash tracks *retroactive taking*,
not closedness.** Ranked by severity: silently removing shipped features
(MinIO gutting its community console → forks, project written off) > 
relicensing a hyperscaler-dependency core (HashiCorp→OpenTofu;
Redis→Valkey, then capitulation back to AGPL) > company-size walls on free
binaries (Teleport 16's <100-employee/<$10M cap — churn and resentment, but
no fork because source stayed AGPL-compilable) > permissive→copyleft with
everything still free (Zitadel, announced early: grumbling, no fork) >
**a proprietary layer drawn correctly on day one** (Tailscale/Headscale,
Pomerium Zero, NetBird's AGPL control plane + paid enterprise glue): zero
backlash, because nothing was ever taken away. Also: Tailscale *reversed*
its SSO paywall ("security isn't a luxury") — an identity vendor paywalling
the SSO protocol itself lands on sso.tax and is reputationally untenable,
because SSO *is* the product. The defensible line (per the sso.tax debate)
is charging for *governance around* identity, never the protocols.

**The line for OpenIDX:**
- **Apache-2.0 forever, never retroactively narrowed:** all protocols
  (OIDC/SAML/SCIM/MFA/passkeys), the IdP, base governance (requests,
  approvals, SoD, campaigns), PAM core (vault, rotation, brokered sessions,
  recording), Ziti orchestration + BrowZer, multi-tenancy + RLS, audit
  hash-chain, agents. This *is* the moat and the funnel.
- **Commercial (source-available `ee/`, Infisical/Authentik pattern), new
  features only:** compliance packs (KVKK/BDDK/NIS2/DORA report templates +
  evidence automation), premium connectors (HR sources, EDR/MDM, ITSM),
  white-label/MSP orchestration + usage metering/chargeback, advanced
  retention/legal-hold policies, FIPS/air-gap build channel, and the SLA
  ladder itself.
- **Fallback if protection is ever needed:** the Zitadel route (AGPL core,
  Apache SDKs, announced early) — never BUSL/SSPL.
- **CRA note:** monetizing makes OpenIDX a CRA "manufacturer" (the light
  open-source-steward regime won't apply), and identity/PAM software sits in
  **Annex III Class I "important products"** — see §8.6.

### 8.4 Packaging and pricing

Anchors: Authentik Enterprise $5/user/mo (+$0.02 external, Plus from
$20K/yr); NetBird $6/$12; Pomerium $7; Tailscale $8/$18; Infisical Pro
$18/identity; Phase Two Keycloak hosting $149→$2,499/mo; Keycloak
enterprise-support bundles ~$42K–90K/yr; ceiling: Entra Suite $12/user/mo
list, stacked incumbents $33–65/user/mo (§5.3).

| Edition | Price | Contains |
|---|---|---|
| **Community** | Free, self-hosted | Everything protocol + all four pillars' core (§8.3) |
| **Enterprise Self-Hosted** | **$4–6 /internal user/mo** (annual; floor ~$6–8K/yr) | `ee/` features, ticket support, security-advisory feed |
| **Enterprise Plus / Regulated** | **from $25–40K/yr** | SLA ladder (to 24×7), air-gap/FIPS-track builds, sovereign compliance packs, named engineer, escrow |
| **Managed Dedicated** | Enterprise price + hosting | Single-tenant instance operated in the customer's region/cloud — sovereignty as a service (the "your instance, your soil" offer; *note: the platform is multi-tenant-capable — dedicated is a positioning choice, not an architectural constraint*) |
| **MSP / White-label** | per-active-user, ~20–30% partner margin, no minimums | Multi-tenant console, white-label branding (shipped), per-tenant metering (Wave A4), NFR licenses, monthly month-end billing (the Duo mechanic) |

**The TCO one-pager:** 500-user company — OpenIDX Enterprise ≈ $15–30K/yr
+ infrastructure vs $200–400K+ stacked list (§5.3). The long-standing
"70–80% savings" README claim is now *substantiated by third-party pricing
data* — publish the math.

### 8.5 Channels and procurement mechanics

- **AWS Marketplace private offers** — fees now 3% (<$1M) / 2% / 1.5%, and
  buyers burn committed cloud spend (EDP/MACC): the cheapest procurement
  shortcut available to a two-person vendor. List early, even self-hosted
  (BYOL + paid support listing).
- **Türkiye:** yerli malı certification (15% tender advantage), 2–3 local
  SI/MSSP partnerships, KVKK/BDDK compliance-pack co-marketing.
- **EU:** partner with EU hosting providers (the elest.io/Univention
  pattern), openDesk-adjacent public-sector channels, NIS2/DORA content.
- **MSP program:** Registered/Silver/Gold tiers, PSA integrations
  (ConnectWise/Halo) on the roadmap, portal after Wave A2.

### 8.6 Trust artifacts and the compliance calendar

| When | Artifact | Cost (benchmarked) |
|---|---|---|
| Now (after Tier-1 fixes) | **Product pentest** + published summary | $8–15K |
| Now | SBOM + cosign-signed images + SECURITY-SUPPLY-CHAIN.md (D7) | eng time |
| **By 2026-09-11** | **CRA vulnerability-reporting readiness** — coordinated disclosure policy, 24-h early warning to ENISA for actively exploited vulns, 72-h notification, 14-day report. *Seven weeks away.* CRA Annex III **Class I item (1) verbatim covers "identity management systems and privileged access management software"**; monetizing (paid support/SLA/hosting) makes OpenIDX a full "manufacturer" — the light open-source-steward regime will not apply. Full CE obligations 2027-12-11; self-assessment allowed only if harmonised standards are applied in full (first CEN/CENELEC deliverables expected Q3 2026 — if they slip, small vendors face notified-body queues). Early CE readiness is a *moat*: from Dec 2027 it penalizes DIY Keycloak assemblies and non-EU-focused rivals | process + docs; ~1 security-eng headcount of process + low-five-figures €/yr from 2027 |
| Q4 2026 | **ISO 27001** (EMEA buyers weight it over SOC 2) | ~$15–25K all-in |
| H1 2027 | **SOC 2 Type II** (Type I fast, Type II observation window opened same day) — before the first US mid-market deal | ~$30–50K year one (Vanta/Drata ~$10–25K + auditor $12–45K + pentest) |
| ongoing | Cyber/E&O insurance | $1.5–5K/yr |

Self-hosting partially relaxes buyer demands (no customer data at the
vendor; "audit the code" is a real answer) — but SOC 2 covers the
*build/release pipeline*, which supply-chain-aware buyers now audit anyway.

### 8.7 The first ten customers (concrete sequence)

1–3: Türkiye design partners — one BDDK-regulated bank/fintech (PAM +
session recording + data-locality lead), one public institution (yerli malı
+ BrowZer clientless for contractors), one industrial (OT vendor-access
pattern: hop mode + recorded Guacamole).
4–6: EU mid-market via NIS2/DORA content + Keycloak-migration webinar
(importer as the hook) — DACH/Nordics.
7–8: MSP white-label pilots (after Wave A2) — one Turkish MSSP, one EU MSP.
9–10: OSS-first engineering orgs via the Auth0-refugee/Teleport-restriction
angle (importer + TCO calculator + `openidx connect` beta).

**Sales assets to build (small, this quarter):** the five-proof-point demo
script (§6.3), the TCO calculator, four battle cards (§6.2 rows), a
reference architecture + published benchmark (D6), and a trust page
(pentest summary, SBOM, CRA posture, compliance-pack list).

### 8.8 Honest revenue math

- **Year 1** (from launch): 5–10 design partners → 3–6 convert to paid →
  **$50–150K ARR**, plus first MSP pilot revenue.
- **Year 2:** 30–60 customers × $15–60K ACV → **$1–2M ARR** — precisely the
  waterline where Zitadel (150 customers), NetBird (Series A), and Infisical
  (cash-flow-positive) sat. Fundable *or* sustainable; the sovereign-EMEA
  unified-platform wedge is owned by none of the fifteen comparables.
- The bus-factor objection (§10) is answered with runbooks, escrow, and the
  Apache-2.0 core itself — "you can't be locked in" is the closing argument.

---

## 9. 12-month commercialization roadmap

Product waves (§3.3) + deal-blockers (§7.1) + GTM (§8) on one calendar:

**Q3 2026 (now → Sep)** — *"Make it evaluable."*
- Product: Tier-1 landmine fixes (push FCM v1/APNS, magic-link send, SAML
  `goxmldsig`, consent, delete mock helper, voice-MFA decision); Wave A1
  (fabric event ingestion) started; SIEM forwarder; Ziti v2.0/Raft upgrade
  plan (v2 routers need v2 controllers).
- Commercial: hygiene PR (D2 — README rewrite: *multi-tenant, RLS-enforced*
  as the headline); quickstart + 10-min video (D3); pentest commissioned
  (D1); SBOM/cosign (D7); **CRA disclosure process by Sep 11**; licensing +
  open-core boundary published (D5); TCO calculator + battle cards.
- Milestone: **Show HN / r/selfhosted launch** once TTFV < 15 min. First 2
  design partners signed (Türkiye).

**Q4 2026 (Oct → Dec)** — *"Make it governable end-to-end."*
- Product: Wave A2 (per-org overlay scoping) + A3 (mid-session posture
  revocation); outbound SCIM client build begins (the Tier-2 #1);
  Keycloak importer; detective SoD sweep; break-glass + dual-control.
- Commercial: ISO 27001 program start; design partners 3–6; first `ee/`
  features (compliance packs, retention/legal-hold policies); AWS
  Marketplace BYOL listing; Türkiye SI partnership #1.
- Milestone: **first paid contract** (target: Türkiye regulated).

**Q1 2027 (Jan → Mar)** — *"The differentiator demo."*
- Product: Wave B1/B2 (JIT network grants; certification-revoke → policy
  detach → the <30 s revoke-to-packet demo complete); outbound SCIM GA;
  HR connector #1 (BambooHR); RFC 8693 + DCR (agent substrate); Okta/Auth0
  importers; Wave A4 metering.
- Commercial: SOC 2 Type I + Type II window opens; MSP portal beta with 2
  pilot partners; published benchmarks (D6); i18n first pass (TR + DE).
- Milestone: **5+ paying customers; MSP program soft launch.**

**Q2 2027 (Apr → Jun)** — *"Own the frontier narrative."*
- Product: Wave C1 (`openidx connect` native access) beta; EDR/MDM
  ingestion; SSF/CAEP build (Wave D2) — announce "first OSS SSF/CAEP with
  native network termination"; MCP gateway spike on `openziti/llm-gateway`.
- Commercial: MSP program GA; EU partner #2; case studies ×3; SOC 2 Type II
  report lands (if window opened in Q1).
- Milestone: **10 customers / $250–500K ARR run-rate; decide raise-vs-bootstrap
  from a position of proof.**

**KPIs to instrument now:** time-to-first-value (target <15 min); GitHub
stars + Discord members (funnel proxy); *production deployments* (opt-in
telemetry ping — the number that predicts revenue); design partners signed;
POC→paid ≥50%; ARR; mean support first-response time.

---

## 10. Risks

| Risk | Why it's real (July 2026 evidence) | Mitigation |
|---|---|---|
| **Ziti-ecosystem dependency** — small community (~4.3k stars, ~84 active forum users/mo), single-vendor governance (docs now redirect to netfoundry.io), v2.0 breaking changes | The moat substrate is steered by a company that monetizes the same up-stack layer we target | Track upstream tightly (v2/Raft bump planned, not reactive); keep the Ziti coupling behind `internal/access` seams; stay friendly — OpenIDX grows NetFoundry's ecosystem and a partnership (their SaaS fabric + our control plane) is a legitimate outcome; worst-case the proxy/Guacamole/WireGuard-less paths still work without the overlay |
| **NetFoundry moves up-stack first** — Frontdoor, zLAN, MCP/LLM gateways shipped Nov 2025–Jun 2026 | They have $15M+, Cisco backing, and the fabric's authors | Differentiate where they don't go: self-hosted white-label multi-tenancy, IAM/IGA/PAM fusion, Apache-2.0 posture vs their quote-only tiers; speed on Waves A–B |
| **Incumbents finish stitching** — PANW×CyberArk closed, Okta×Axiom, Delinea×StrongDM | The consolidation window (§5.2) narrows as integrations mature over 2–4 years | Sell *now* into the window; make "actually one system" demoable (kill switch, Access 360) in every touch |
| **Mindshare gravity of WireGuard mesh** — NetBird 27.5k stars/$10M, Tailscale ~40k customers | Simplicity buyers default to mesh VPN and never evaluate us | Don't fight mesh on simplicity; lead with what mesh can't do (dark services, clientless BrowZer, PAM-over-overlay, governance) and match their TTFV with the quickstart (D3) |
| **A pentest hits a remaining landmine** — Tier-1 items in §7.2 still open | The July 10 "hollow layer detonates in a POC" risk is reduced but not zero (push, magic link, SAML crypto, mock helper) | Tier-1 fixes are days-to-weeks; complete before commissioning the D1 pentest; keep the "advertised = working" rule enforced in CI |
| **Single-maintainer bus factor & velocity concentration** | 59 commits/11 days is one person's pace; buyers ask "what if you get hit by a bus?" | Support contracts backed by documented runbooks; grow 1–2 contributors/contractors around connector SDKs; escrow arrangements for enterprise deals |
| **Compliance calendar slips** — SOC 2 Type II needs a 3–6-month observation window | Every month unstarted pushes the enterprise segment a month right | Start the program in July; sell design-partner deals (which tolerate in-progress compliance) meanwhile |
| **Single-Postgres scale ceiling found by a customer** | No published benchmarks (D6); the unified-store moat is also the bottleneck | Benchmark before customers do; document read-replica path; audit-store carve-out is the designed escape valve (per the 2026-07-14 review) |
| **Open-core boundary backlash** | Teleport's CE restriction and HashiCorp's BUSL each burned community trust | Draw the line where the community precedent is safest (§8.3): core stays Apache-2.0 forever; commercial = white-label/MSP orchestration, compliance packs, support — never yank existing OSS features |
