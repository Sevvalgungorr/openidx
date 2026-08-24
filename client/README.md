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
