# `openidx_engine` — Flutter ↔ Go engine bridge (mobile)

Federated Flutter plugin that lets the mobile app drive the **same** Go OpenIDX
engine as the desktop client. Where the desktop reaches the engine over a local
control socket, mobile links the engine **in-process** via its
[`gomobile`](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile) binding
(`agent/mobile`) and calls it across a Flutter `MethodChannel('openidx_engine')`.

```
Dart  OpenidxEngine  ──MethodChannel──▶  Swift OpenidxEnginePlugin ──▶ Mobile.*   (Engine.xcframework)
      (lib/openidx_engine.dart)          Kotlin OpenidxEnginePlugin ──▶ mobile.Mobile.*  (engine.aar)
                                                                        └──▶ agent/mobile (Go) ─▶ control.Engine
```

Each gomobile function returns a **JSON string** (or a Go `error`). The plugin
does no parsing — it returns the raw JSON to Dart, where `MobileEngineClient`
(in the app package) decodes it with the shared Phase-1 `models.dart`
factories, so mobile and desktop decode identical wire shapes.

> ⚠️ **Written, not built here.** There is no Flutter/Dart SDK (nor the
> `gomobile` toolchain) in this repo checkout, so this plugin has not been
> compiled or linked locally. It is written to the gomobile binding contract in
> `agent/mobile/mobile.go` and **verified in CI** by
> `.github/workflows/client-mobile-build.yml`, which builds the bindings, wires
> them in, and runs `flutter analyze` / `flutter test` / `flutter build`.

## Producing the native engine artifacts

Requires Go + the gomobile toolchain (`go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init`).
Run from the repo root:

```bash
# iOS — Swift module `Mobile`
gomobile bind -target=ios     -o Engine.xcframework ./agent/mobile

# Android — Kotlin/Java class `mobile.Mobile`
gomobile bind -target=android -o engine.aar         ./agent/mobile
```

## Where to drop them so the plugin links

- **iOS:** copy `Engine.xcframework` to
  `client/plugins/openidx_engine/ios/Frameworks/Engine.xcframework`.
  The podspec's `vendored_frameworks` links it and `import Mobile` resolves.
- **Android:** copy `engine.aar` to
  `client/plugins/openidx_engine/android/libs/engine.aar`.
  `build.gradle` picks it up via the `flatDir` repo + `implementation(name: 'engine', ext: 'aar')`,
  and `import mobile.Mobile` resolves.

These artifacts are build outputs and are **not** committed. CI produces and
stages them on every run.

## API

`class OpenidxEngine` mirrors the gomobile surface 1:1:
`start(configDir)`, `status()`, `login()`, `logout()`, `enroll(code)`,
`posture()`, `pamList()`, `pamConnect(entryId)`,
`pamRequest(entryId, reason)`, `zitiDial(service)`, `zitiClose(service)`.

String-returning methods return the JSON body; void methods complete on success.
Go errors surface as `PlatformException`/`FlutterError` and are converted to the
app's `EngineException` in `MobileEngineClient`.
