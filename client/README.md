# OpenIDX Desktop Client (`openidx_client`)

Phase 1 of the OpenIDX native-client program: a **Flutter desktop app** (Windows /
macOS / Linux) that acts as a thin **shell** over the local Go **engine**
(`openidx-agent serve`, built in Phase 0). The shell renders enrollment, login,
device posture, and Privileged Access (PAM); all real work — OIDC login, Ziti,
posture checks, PAM brokering — happens in the engine, reached over a **local
control socket**.

> ⚠️ **This code is written, not built, in this repo checkout.** There is no
> Flutter/Dart SDK in the authoring environment, so it has not been compiled,
> `flutter analyze`d, or `flutter test`ed here. It is written to the exact
> engine control contract below and is **verified in CI** via the Flutter SDK
> (see `.github/workflows/client-desktop-build.yml`, which runs
> `flutter analyze`, `flutter test`, and `flutter build` on all three desktop
> OSes).

## Architecture

```
┌────────────────────────────┐        local control socket        ┌────────────────────┐
│  Flutter desktop shell     │  HTTP/1.1 over UDS (posix)          │  openidx-agent     │
│  (this package)            │  ── or ── loopback TCP + Bearer     │  serve (Go engine) │
│   ui/  →  state/ (riverpod)│      (Windows)                      │                    │
│         →  engine/ client  │ ───────────────────────────────►   │  /status /posture  │
│         →  engine/ supervisor spawns/attaches the engine         │  /login /enroll …  │
└────────────────────────────┘                                     └────────────────────┘
```

- **`lib/engine/`** — transport + models. `EngineClient` (abstract) →
  `DesktopEngineClient` (concrete). `EngineSupervisor` spawns or attaches the
  engine process.
- **`lib/state/`** — Riverpod providers (`engineClientProvider`,
  `statusProvider`, `postureProvider`, `pamEntriesProvider`, plus
  `engineActionsProvider` for mutations).
- **`lib/ui/`** — `MaterialApp` (light/dark), screens, and the tray controller.

### How the client dials the engine

The transport is platform-dependent (implemented in
`lib/engine/desktop_engine_client.dart`):

- **Non-Windows (Linux/macOS):** a **Unix-domain socket** at
  `${XDG_RUNTIME_DIR:-<tmpdir>}/openidx-agent.sock`. We use `dart:io`
  `HttpClient` with a custom `connectionFactory` that dials the UDS via
  `Socket.startConnect(InternetAddress(<path>, type: unix), 0)`, so we get full
  HTTP/1.1 semantics over the socket. The socket's filesystem permissions are
  the trust boundary — **no auth token**.
- **Windows:** the engine publishes
  `%ProgramData%\OpenIDX\agent\control-endpoint.json` =
  `{ "addr": "127.0.0.1:<port>", "token": "<hex>" }`. The client reads that
  file, connects to the loopback TCP address, and sends
  `Authorization: Bearer <token>` on **every** request.

Endpoint discovery lives in `EngineEndpointResolver.resolve()`.

### How the app supervises `openidx-agent serve`

`lib/engine/engine_supervisor.dart`:

1. On boot, `start()` first probes `/status`.
2. If the engine already answers (e.g. a system service — systemd / launchd /
   Windows Service — is running it), it **attaches** and does not manage the
   lifecycle.
3. Otherwise it locates the `openidx-agent` binary (env override
   `OPENIDX_AGENT_BIN` → bundled next to the app → `bin/` sibling → PATH),
   `Process.start(['serve'])`, and `waitReady()` polls `/status` until reachable
   (with a timeout).
4. On quit, a **spawned** engine is terminated; an **attached** one is left
   running.

### Screen flow

Driven by live `/status` in `lib/ui/app.dart`:

- **not enrolled** → `EnrollScreen` (paste enrollment code → `/enroll`)
- **enrolled, not logged in** → `LoginScreen` ("Sign in with OpenIDX" → `/login`)
- **enrolled + logged in** → `HomeScreen` (status card + posture summary + nav)
  - → `PamScreen` (list `/pam/entries`; **Connect** opens the launch URL via
    `url_launcher`; **Request** submits `/pam/request` for approval-gated
    entries)
  - → `SettingsScreen` (server URL, sign out, quit)

A system-tray icon (`lib/ui/tray.dart`) provides Open / Sign in-out / Quit and
close-to-tray behaviour.

## Engine control contract

Transport as above. Routes (JSON in/out):

| Method | Path            | Body                                   |
| ------ | --------------- | -------------------------------------- |
| GET    | `/status`       | —                                      |
| GET    | `/posture`      | —                                      |
| GET    | `/pam/entries`  | —                                      |
| POST   | `/login`        | —                                      |
| POST   | `/logout`       | —                                      |
| POST   | `/enroll`       | `{"code":"..."}`                       |
| POST   | `/pam/connect`  | `{"entry_id":"..."}`                   |
| POST   | `/pam/request`  | `{"entry_id":"...","reason":"..."}`    |
| POST   | `/ziti/dial`    | `{"service":"..."}`                    |
| POST   | `/ziti/close`   | `{"service":"..."}`                    |

Response shapes are mirrored 1:1 by the `fromJson` models in
`lib/engine/models.dart` (`AgentStatus`, `User`, `EnrollResult`, `Posture` +
`PostureCheck`, `PamEntry`, `PamConnectResult`).

## Getting started

The macOS / Linux / Windows **runner directories are SDK-generated and are
intentionally not committed** (they are in `.gitignore`). Materialize them, then
build:

```bash
cd client

# 1. Generate the platform runner directories (macos/, linux/, windows/).
flutter create --platforms=windows,macos,linux .

# 2. Fetch dependencies.
flutter pub get

# 3. Run on your desktop OS.
flutter run -d macos      # or: -d linux  |  -d windows

# Quality gates (also run in CI):
flutter analyze
flutter test
flutter build macos       # or: linux | windows
```

### Bundling the engine sidecar

Package the `openidx-agent` binary next to the app (or install it as a system
service). At runtime the supervisor discovers it via `OPENIDX_AGENT_BIN`, then
next-to-app, then a `bin/` sibling, then PATH. The CI workflow contains a
placeholder step for wiring the sidecar into the build bundle.

## Layout

```
client/
├── pubspec.yaml
├── analysis_options.yaml
├── .gitignore
├── README.md
├── lib/
│   ├── main.dart
│   ├── engine/
│   │   ├── models.dart
│   │   ├── engine_client.dart
│   │   ├── desktop_engine_client.dart
│   │   └── engine_supervisor.dart
│   ├── state/
│   │   └── providers.dart
│   └── ui/
│       ├── app.dart
│       ├── tray.dart
│       └── screens/
│           ├── login_screen.dart
│           ├── enroll_screen.dart
│           ├── home_screen.dart
│           ├── pam_screen.dart
│           └── settings_screen.dart
└── test/
    └── engine_client_test.dart
```

---

## Phase 2b — Mobile (iOS / Android)

The **same** `openidx_client` package also runs on iOS and Android. The
difference is purely transport: where desktop reaches the engine over a local
control socket, mobile links the engine **in-process** via its gomobile binding
(`agent/mobile`, Phase 2a) and calls it across a Flutter `MethodChannel`.

> ⚠️ **Written, not built here.** As with the desktop shell, there is no
> Flutter/Dart SDK (nor the `gomobile` toolchain) in this checkout, so none of
> the mobile code has been compiled, `flutter analyze`d, or `flutter test`ed
> locally. It is written to the gomobile binding contract in
> `agent/mobile/mobile.go` and the backend HTTP contracts, and is **verified in
> CI** by `.github/workflows/client-mobile-build.yml` (builds the
> `Engine.xcframework`/`engine.aar`, `flutter create --platforms=ios,android`,
> then `flutter analyze` / `flutter test` / `flutter build apk` /
> `flutter build ios --no-codesign`).

### Engine transport on mobile

```
Dart EngineClient (shared contract + models.dart)
      │  EngineClientFactory picks by platform
      ├─ desktop → DesktopEngineClient  ── HTTP over control socket (Phase 1)
      └─ mobile  → MobileEngineClient   ── MethodChannel('openidx_engine')
                                              │
                          plugins/openidx_engine (federated plugin)
                             Swift OpenidxEnginePlugin → Mobile.*  (Engine.xcframework)
                             Kotlin OpenidxEnginePlugin → mobile.Mobile.*  (engine.aar)
                                              │
                                     agent/mobile (Go) → control.Engine
```

The gomobile funcs return the **same JSON shapes** the control server emits, so
`MobileEngineClient` decodes them with the identical Phase-1 `models.dart`
factories — desktop and mobile stay wire-compatible by construction. See
`plugins/openidx_engine/README.md` for how to produce and drop the native
artifacts.

### Non-engine journeys (HTTP)

Enroll / PAM / Ziti go through the engine. The remaining journeys (MFA,
governance, notifications) talk to the backend gateway **directly** over HTTP,
mirroring the React-Native app's `src/lib/api.ts`:

- `lib/api/api_client.dart` — token-authed `dio` client; `Bearer` injection,
  `X-Org-Slug`, single-flight refresh-on-401 via `/oauth/token`.
- `lib/api/auth.dart` — PKCE via `/oauth/native/login-init`, then passkey
  (`/oauth/passkey-begin`/`finish`) or a browser PKCE fallback; tokens in
  `flutter_secure_storage`.
- `lib/api/{mfa,governance,notifications}.dart` — the endpoint wrappers.

### Mobile UI + platform

- `lib/ui/mobile_shell.dart` — bottom-nav shell (Codes / Approvals / Access /
  Settings), used when `Platform.isIOS || isAndroid`; desktop keeps its
  window/tray shell.
- `lib/ui/screens/mobile/` — authenticator (offline TOTP), push number-match
  approval, governance approvals, my-access, notifications.
- `lib/features/totp.dart` — self-contained RFC 6238 TOTP + base32 (codes are
  generated on-device; secrets never leave the keystore).
- `lib/mobile/app_lock.dart` — biometric app-lock (`local_auth`) on cold start
  and after idle, with a graceful no-biometric fallback.
- `lib/mobile/deep_links.dart` — `app_links` handling for
  `openidx://oauth-callback` and `openidx://approve/<id>`.

### Mobile file map (Phase 2b additions)

```
client/
├── plugins/openidx_engine/            # federated Dart↔gomobile plugin
│   ├── lib/openidx_engine.dart
│   ├── ios/Classes/OpenidxEnginePlugin.swift
│   ├── android/.../OpenidxEnginePlugin.kt
│   └── README.md
├── lib/
│   ├── engine/mobile_engine_client.dart
│   ├── engine/engine_client_factory.dart
│   ├── api/{api_client,token_store,auth,mfa,governance,notifications}.dart
│   ├── features/totp.dart
│   ├── mobile/{app_lock,deep_links}.dart
│   ├── state/mobile_providers.dart
│   └── ui/
│       ├── mobile_shell.dart
│       └── screens/mobile/{authenticator,push_approve,approvals,my_access,notifications}_screen.dart
└── test/{mobile_engine_client_test,totp_test}.dart
```
