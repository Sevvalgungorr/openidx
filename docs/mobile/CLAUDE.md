# CLAUDE.md — OpenIDX Mobile (native Android)

> **Where this file belongs:** the ROOT of the native Android project (the Kotlin/Jetpack
> Compose app, package `org.tdv.openidx`). It is placed here under `docs/mobile/` only as a
> handoff template until that project is in version control (see **BLOCKER E1**). Move it to
> the mobile repo root and fill the `TODO(dev):` lines.

## What this project is

The OpenIDX mobile client: a **native Kotlin / Jetpack Compose** Android app (NOT React Native —
the old `openidx-mobile` Expo repo is dead, see the findings report §0). It is a thin client over
the OpenIDX backend for approvals, PAM remote access, MFA (TOTP/push/passkey), and notifications,
and (target state) reaches dark services over the **OpenZiti** overlay.

- **Package:** `org.tdv.openidx` · **Deep-link scheme:** `openidx://` (registered in the manifest)
- **Stack (from APK inspection):** Kotlin 2.0.21, Gradle 8.11.1, Jetpack Compose, `kotlinx.serialization`,
  `androidx.credentials` + `play-services-fido` (passkeys), OAuth via Custom Tabs.
- **Backend base URL:** `https://openidx.tdv.org` (prod box). Auth is **Bearer JWT** (RS256, from the
  OAuth v1 flow) — the app has **no cookie session**.

**Companion docs (read both before starting):**
- `docs/OpenIDX-Mobile-Developer-Action-Plan.md` — the backlog/spec (task IDs A*/Z*/E*/G* used below).
- `OpenIDX-Mobile-Findings-Report.md` — the empirical test findings these tasks come from.

## BLOCKER E1 — read first

The native source must be committed and CI-wired before any mobile task is actionable. Until then,
every "fix" is blind. If you are an agent and the source isn't present, STOP and report E1.

## Build / test / lint

`TODO(dev): fill these in from the real project — do not guess. The rest of this file assumes them.`

```bash
# TODO(dev): assemble debug APK        e.g.  ./gradlew assembleDebug
# TODO(dev): unit tests                 e.g.  ./gradlew testDebugUnitTest
# TODO(dev): instrumented/UI tests      e.g.  ./gradlew connectedDebugAndroidTest
# TODO(dev): lint + format              e.g.  ./gradlew ktlintCheck detekt
# TODO(dev): install to device          e.g.  ./gradlew installDebug
```

**Gate before every commit:** build + unit tests + lint all green. Add crash/error reporting to the
release build (**E9**) — release logcat currently has zero app logs, which makes field diagnosis
impossible.

## Backend contract (what the app calls, and how it's protected)

The backend fails closed: the auth middleware returns **401 on any missing/invalid token** and only
trusts an RS256-JWKS-verified `sub`. Endpoints fall in four tiers:

| Tier | Auth | Endpoints the app uses |
|------|------|------------------------|
| Dark front door | session **or** enrollment token | `POST /api/v1/access/enroll` (mints the Ziti JWT — **the app must call this**, it currently doesn't) |
| Authenticated user | Bearer JWT | `/api/v1/access/pam/entries`, `/pam/my-entry-requests`, `/pam/entries/{id}/connect`, `/governance/my-approvals`, `/identity/notifications`, `/identity/mfa/totp/*`, `/identity/mfa/push/*` |
| Admin | Bearer JWT + admin role | approvals decisions, entry CRUD (not typical for this app) |
| Device/agent | enrollment/agent credential | `POST /api/v1/access/agent/enroll/oauth`, `/agent/report` |

If an authed endpoint returns 401 while others on the same token succeed, it is very likely a
**backend/edge** issue (A1/A2/A3) — do NOT paper over it client-side beyond the refresh rule below.

## Client conventions (non-negotiable)

1. **401 handling (A7):** on 401, attempt a **token refresh once**; only route to login if refresh
   also fails. A single endpoint's 401 must NEVER wipe the session / log the user out.
2. **Null-safe lists (A6):** the backend sometimes returns `null` for list fields. Every
   `List<T>` deserialization must default: `?: emptyList()`. Never let one null list crash a screen.
3. **WebView for PAM sessions (A4):** the Guacamole client needs JS + DOM storage on,
   `mediaPlaybackRequiresUserGesture=false`, hardware acceleration, and a **non-zero measured size**
   (Guacamole derives its display size from the WebView — a zero-size view renders a black screen).
4. **No secrets in logs / URLs:** the Guacamole token rides in the connect URL fragment — keep it out
   of persisted WebView history where feasible.
5. **Compose + kotlinx.serialization** idioms; keep networking in a single typed HTTP layer so the
   refresh rule (1) lives in one place.

## OpenZiti — dark services (mirror the Windows client)

Target: reach services not publicly routable, the way the desktop client does. The reference is
`agent/internal/ziti/dialer.go` in the backend repo:

- Embedded **per-service dial**, no TUN/VPN, no elevation.
- `Bridge(service)` opens a `127.0.0.1:0` TCP listener and pumps each connection to the named Ziti
  service both ways with stream copies; returns the loopback address the local client points at.

**Android equivalent to build:**
- **Z4:** integrate `org.openziti:ziti-android`; wrap `enroll(jwt)`, `status()`, `serviceAvailable(name)`,
  `dial(name)`. Store the enrolled identity in the app keystore.
- **Z5:** port `Bridge()` to Kotlin — a `ServerSocket` on `127.0.0.1:0`, per accepted socket
  `zitiContext.dial(service)` + copy streams on IO dispatchers; return the local port. Start on Connect,
  stop on session close.
- **Switch on `reach_mode`:** when a PAM entry reports `reach_mode == "ziti"`, point the Guacamole
  WebView at `http://127.0.0.1:<port>/...`; when `"direct"`, keep today's behavior.

**Blocked on backend/infra (don't burn SDK effort before these land):** Z1 real controller FQDN
(today's JWT `iss` is `localtest.me` → resolves to 127.0.0.1 on a phone), Z2 fresh enrollment JWT per
call (current one is expired/cached), Z3 an actual `ziti_enabled` PAM entry to test against. Backend
design: `docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md`.

**Ziti done =** on mobile data (off corporate WiFi), enroll → `status()` active → connect to a
`ziti_enabled` entry → WebView renders through the `127.0.0.1` bridge.

## Verify-first discipline

Before "fixing" a reported backend bug, confirm it reproduces against the **current** backend binary
through the **real edge** — several findings may be edge/deploy gaps already fixed in `main`. Client
changes should assume the backend contract above, not work around a possibly-stale deployment.

## Definition of done (per task)

Code + unit test (and a UI test for screen-level bugs like A4) + lint green + the specific proof named
in the action plan's bug-close table (e.g. A4: the same `connect_url` that renders in phone Chrome now
renders in-app). Reference the task ID (A*/Z*/E*) in the commit message.
```
