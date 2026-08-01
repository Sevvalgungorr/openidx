# Windows Application Delivery

Deliver individual Windows applications (SSMS, etc.) to the browser — passwordless,
recorded, and placed across a host pool — without a full desktop. This is the
productized form of the RemoteApp launch shipped in #624/#625.

## How it works

```
User clicks Launch (Windows Apps page)
      │
      ▼
Placement: pick a host in the app's pool with free capacity that the user
           isn't already occupying (GUACAMOLE-1951)
      │
      ▼
Same gates as a PAM connect on the chosen host: RBAC + JIT approval
      │
      ▼
Vault Use(): the host credential is decrypted server-side and injected
      │
      ▼
Guacamole RDP with remote-app=||<alias>, disable-gfx=true  (GUACAMOLE-2123)
      │
      ▼
RDS/Windows host runs ONLY that published app → browser tab
      │
      ▼
Session recorded + audited; reachable directly or over the Ziti overlay
```

- **Host = a PAM entry** (`entry_type=windows_app_host`). It inherits vault
  injection, linked credentials, Ziti reach, recording, approval and checkout
  from the PAM module — no separate host machinery.
- **App = a `windows_apps` row**, bound to a single host or a **pool** of
  interchangeable hosts. Apps discovered from the host's `TSAppAllowList` are
  marked **verified** (published & launchable); installed-but-unpublished apps
  import for reference.
- **Placement** honors Guacamole's one-connection-per-launch reality
  ([GUACAMOLE-1951](https://issues.apache.org/jira/browse/GUACAMOLE-1951)): a
  second app for a user goes to another host with capacity; if none is free the
  console offers an explicit "disconnect & launch here" rather than silently
  killing a session.

## Setting up a host

Windows Server + RDS is the multi-session deployment; Windows 10/11
Pro/Enterprise also works but serves **one concurrent RemoteApp session** — use
a pool to scale those.

1. On the host, publish the apps and enable RDP/NLA with the bundled script
   (elevated PowerShell):

   ```powershell
   .\scripts\windows\Prepare-OpenIDXAppHost.ps1 -Publish -AppsJson (Get-Content apps.json -Raw)
   ```

   It enables RDP, requires NLA, and registers each app under
   `TSAppAllowList\Applications\<alias>` **with the allowlist enforced**. It
   never sets `fAllowUnlistedRemotePrograms`.

2. Report the host's published apps + posture and import them into OpenIDX:

   ```powershell
   .\scripts\windows\Prepare-OpenIDXAppHost.ps1 -Report   # prints JSON
   ```

   Paste the JSON into **Windows Apps → Import from host** (or let the OpenIDX
   agent post it). Verified apps become launchable immediately.

3. In OpenIDX, add the host as a **Windows App Host** connection (credential
   vaulted), then group hosts into a **pool** and set each host's
   `max_sessions`.

## Security & containment

RemoteApp restricts *which* app opens, not *what the user can reach from it*.
Treat a published-app host as a semi-trusted boundary and harden it:

- **Never allow unlisted programs.** `fAllowUnlistedRemotePrograms=1`
  (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`) lets **any**
  program — including `cmd.exe`/`powershell.exe` — run as a RemoteApp, defeating
  the allowlist. OpenIDX **never** sets it, the prep script refuses to, and the
  console shows a **prominent warning banner** for any host reporting it enabled.
  Keep the allowlist enforced (`fDisabledAllowList=0`) with explicit per-app
  entries.
- **Assume breakout is possible.** Published apps can escape via File Open/Save
  dialogs (type `cmd`, right-click → Open), Help → browser, and script hosts
  ([GUACAMOLE-1464](https://issues.apache.org/jira/browse/GUACAMOLE-1464): the
  Start menu is reachable from a RemoteApp session). Mitigate with:
  - a **dedicated, low-privilege host** whose user account can reach only what
    the app legitimately needs;
  - **AppLocker or WDAC** allow-listing the specific executables (and blocking
    `cmd.exe`, `powershell.exe`, script hosts) so a breakout can't run anything;
  - reaching databases/targets over the **Ziti overlay** so a compromised host
    still can't see the network directly.
- **No secrets in arguments.** `remote-app-args` appear in the target's process
  list. OpenIDX rejects password-looking args on save and at import, and steers
  to integrated auth (e.g. SSMS `-E`, which signs in as the injected Windows
  identity). Never pass a password on the command line.
- **Credentials never leave the server.** The host credential is vault-decrypted
  in memory and injected into the Guacamole connection; the browser only ever
  receives a connect URL. There is no downloadable `.rdp` file.

## Broker version pinning

Guacamole broker images are pinned to `guacamole/guacd:1.6.0` /
`guacamole/guacamole:1.6.0`. RemoteApp needs FreeRDP 2 (1.6.0's default); a
guacd built against FreeRDP ≥3.4.0 breaks RemoteApp entirely
([GUACAMOLE-2072](https://issues.apache.org/jira/browse/GUACAMOLE-2072), fixed
only in the unreleased 1.6.1). `disable-gfx=true` is forced on every RemoteApp
launch because RemoteApp windows don't repaint with the GFX pipeline on, which
1.6.0 enables by default
([GUACAMOLE-2123](https://issues.apache.org/jira/browse/GUACAMOLE-2123)).

## Where things are

| Component | Path |
| --- | --- |
| Launch core (shared with PAM connect) | `internal/access/pam_launch.go` (`launchPamSession`, `ensureGuacConnection`) |
| App catalog, placement, pools, import | `internal/access/windows_apps.go`, `internal/access/windows_apps_launch.go` |
| Schema | `internal/migrations/sql_v119.go` |
| Host prep / discovery script | `scripts/windows/Prepare-OpenIDXAppHost.ps1` |
| Console | `web/admin-console/src/pages/windows-apps.tsx` |

## App-V and other packaging layers

App-V is a packaging/isolation layer on the session host; RemoteApp is the
delivery layer — they compose, and OpenIDX stays agnostic (an App-V app is just
an alias + a path in `TSAppAllowList`, whose target may be a launcher/virtual
path). Note the lifecycle split: MDOP extended support ended **14 April 2026**,
so the App-V *server* components are out of support and nothing here depends on
them; the App-V *client* in Windows 10/11 Enterprise and Windows Server remains
supported on the OS lifecycle, so standalone/PowerShell-published App-V packages
on an RDS host are a legitimate — but never required — deployment. In a pool the
same alias must resolve to the same app on every member (Microsoft KB 2638538:
per-host alias drift launches the wrong app); discovery records what each host
actually publishes so OpenIDX can flag a mismatch.
