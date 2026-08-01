# Application Virtualization: Assessment & Roadmap

**Status:** Reviewed & corrected — supersedes the original "WASM Application
Virtualization Implementation Plan" draft.
**Verdict:** The direction is right, but the draft conflated two very
different efforts. This document splits them:

- **Track A — available now:** app-level virtualization built entirely from
  components OpenIDX already ships (Guacamole, vault injection, dbproxy,
  Ziti, wasm-ssh). Small, low-risk increments; the first slice (RemoteApp)
  ships with this document.
- **Track B — separate project:** a browser WASM runtime (WebVM/Wasmer
  style). Real potential, but heavy prerequisites and open licensing
  questions. It should be scoped and funded as its own project, not bolted
  onto the console.

---

## 1. What the draft got right

- The three-tier framing (network virtualization → remote desktop → app
  runtime) matches how OpenIDX is actually layered today.
- Passwordless credential flow: correct, and **already implemented** —
  `vaultSvc.Use()` (`internal/vault/store.go`) decrypts server-side only and
  `handlePamConnect` (`internal/access/pam_launch.go`) injects into
  Guacamole. Nothing to build there.
- RemoteApp is the right answer for SSMS and native Windows GUI apps. WASM
  or Wine emulation of SSMS is not viable (Win32/.NET/WPF dependency chain).
- JIT grants, step-up MFA, session recording, instant revocation: all
  existing capabilities the draft correctly reuses rather than reinvents.

## 2. Corrections (things the draft gets wrong)

These are the load-bearing errors; anything built on them would have failed
in week 1.

1. **WebVM is not a free CheerpX.** The draft treats "WebVM (Apache-2.0,
   free)" and "CheerpX (commercial)" as alternatives. They are the same
   engine: the WebVM repository is Apache-2.0, but the x86 virtualization
   core it loads — CheerpX — is proprietary (free for individuals,
   **licensed for organizational/self-hosted use**). There is no
   free-license path to "unmodified psql/mysql in the browser" via WebVM
   for a commercial deployment. This alone reprices most of the draft's P1.
2. **The cited toolchain doesn't exist as written.** `webvm@^0.7.0` and
   `@types/webdav` are not real npm packages; `xterm*` moved to the
   `@xterm/*` scope; `wasmer build --target wasi` and
   `wasmerio/wasmer-action` are not real commands/actions. psql and mysql
   have **no upstream WASI target** — "compile to WASI" means maintaining
   WASIX forks, which is a project in itself.
3. **COOP/COEP would break the existing console.** `Cross-Origin-Embedder-
   Policy: require-corp` (needed for SharedArrayBuffer/WASM threads)
   applied console-wide would break OAuth popups, Guacamole tabs and
   BrowZer embeds. If Track B happens, the runtime must live on an
   **isolated route/subdomain** with its own headers — never on the main
   console origin.
4. **Client-side policy enforcement is not enforcement.** Intercepting SQL
   in xterm.js before send is trivially bypassed (paste, alternative
   client, raw socket). OpenIDX already enforces at the right altitude:
   `internal/access/dbproxy/` is a **PostgreSQL wire-protocol broker** that
   injects vault credentials server-side and decodes/audits every
   Query/Parse message. Read-only mode, statement blocking and row limits
   belong there, not in the terminal widget.
5. **The `GenerateRDPFile` design is an anti-pattern.** Writing
   vault-decrypted credentials into a downloadable `.rdp` file puts
   plaintext secrets on the user's disk — exactly what the vault exists to
   prevent. The correct mechanism (below) keeps credentials server-side.
6. **`wasm_binary BYTEA` in Postgres** — store artifacts in object storage
   with a hash reference, never in row storage.
7. **"Every keystroke logged"** conflicts with credential hygiene (captures
   typed secrets) and duplicates what dbproxy statement audit and Guacamole
   session recording already provide at safer altitudes.
8. The CI/branch-protection section duplicates existing workflows
   (`ci.yml` path-filtering, Required Checks aggregate) and prescribes
   settings (2 approvals, core-maintainers team) that don't match this
   repository.

## 3. What OpenIDX already covers (the draft missed these)

| Draft proposal | Already shipped as |
| --- | --- |
| WASM psql with zero credential exposure + full audit | `internal/access/dbproxy/` — **native** psql/any driver against the broker, short-lived token auth, vault-injected upstream credential, every statement audited |
| Clientless browser SSH terminal | `renderer: wasm-ssh` on SSH entries (xterm session in the console, no Guacamole tab) |
| RemoteApp credential injection | `buildPamGuacParams` forwards entry `settings` to guacd — Guacamole's native `remote-app` / `remote-app-dir` / `remote-app-args` RDP parameters flow through the existing passwordless launch |
| App catalog / launcher | PAM entries + folders + quick links already are the catalog: RBAC, approval, recording, Ziti reach per entry |

## 4. Track A — available now

### 4.1 RemoteApp (ships with this change)

SSMS and any published Windows application now launch as a **single-app
session** through the existing stack — no new backend code:

```
Connect click → RBAC/approval → vault Use() → Guacamole RDP
  with remote-app=||SSMS → RDS host runs only SSMS → browser tab
```

- Admin console: RDP entries gain a *RemoteApp* section (program alias,
  working directory, command-line args) stored in the entry's `settings`
  JSON; aliases are auto-prefixed to Guacamole's `||alias` form.
- Credentials stay vault-injected server-side (no `.rdp` download);
  recording, approval, JIT checkout and Ziti reach apply unchanged, because
  it *is* the normal PAM launch path.
- Host prerequisite (ops, not code): publish the app on the RDS host, e.g.
  `New-RDRemoteApp -CollectionName "OpenIDX Apps" -DisplayName "SSMS"
  -FilePath "...\Ssms.exe"`.

### 4.2 Natural follow-ups (small, independent)

- **dbproxy for MySQL** — second wire protocol behind the same broker
  contract (token auth → vault credential → statement audit).
- **dbproxy policy hooks** — read-only enforcement / statement deny-list at
  the existing audit decode point (the draft's `SQLPolicy`, at the correct
  altitude).
- **RemoteApp presets** — one-click SSMS/VS Code/etc. templates in the
  entry dialog; quick-links surfacing for published apps.

## 5. Track B — browser WASM runtime (separate project)

Worth pursuing **only as its own project** with these gates passed first:

1. **Licensing gate:** a commercial CheerpX agreement, or acceptance that
   only WASI/WASIX-buildable tools are in scope (no unmodified x86
   binaries). This decision shapes everything downstream.
2. **Isolation gate:** dedicated origin/route with COOP/COEP headers,
   proven not to affect OAuth/Guacamole/BrowZer.
3. **Toolchain gate:** at least one real WASIX build (e.g. a Rust-based
   CLI) running end-to-end through a Ziti-proxied WebSocket before any
   catalog/registry work begins.

What carries over from the draft when the gates pass: the app manifest
concept, OPFS scoping, resource limits, and the launcher UI — but the
catalog should be PAM entries with a new `renderer`, not a parallel
`wasm_apps` subsystem.

What OpenIDX gains meanwhile is unaffected: the *product* value the draft
chased — "any app, zero passwords, full audit" — is delivered by Track A on
the components that already exist.

## 6. Decision summary

| Need | Answer | When |
| --- | --- | --- |
| SSMS / Windows GUI apps | RemoteApp via existing Guacamole launch | **Now** (this change) |
| SQL with zero credentials + audit | dbproxy (native psql) | **Shipped**; MySQL next |
| Browser SSH without Guacamole | `wasm-ssh` renderer | **Shipped** |
| CLI tools in-browser (kubectl, redis-cli) | Track B, WASIX builds | Separate project |
| Unmodified x86 Linux apps in-browser | Track B, requires CheerpX license | Separate project |
| Legacy Win16/DOS | Out of scope | — |
