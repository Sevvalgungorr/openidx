import 'package:flutter/services.dart';

/// Thin Dart wrapper over the platform [MethodChannel] that fronts the OpenIDX
/// Go engine's gomobile binding (`agent/mobile`).
///
/// Every method maps 1:1 to a package-level function of the gomobile binding,
/// which returns a **JSON string** (or throws a Go `error`). This class does no
/// JSON parsing — that lives in `MobileEngineClient` in the app package, which
/// reuses the Phase-1 `models.dart` `fromJson` factories. Keeping this layer
/// dumb means the desktop and mobile clients decode identical wire shapes.
///
/// Channel errors (a Go error surfaced as [PlatformException], or a `null`
/// where a string was expected) propagate to the caller, which converts them
/// into the app's `EngineException`.
///
/// > This plugin is written to the gomobile contract and **verified in CI**
/// > (see `.github/workflows/client-mobile-build.yml`); it is not built in the
/// > authoring checkout because no Flutter/Dart SDK is present here.
class OpenidxEngine {
  OpenidxEngine({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(_channelName);

  static const String _channelName = 'openidx_engine';

  final MethodChannel _channel;

  /// Invoke [method] and return its non-null String result.
  ///
  /// Throws [MissingPluginException]/[PlatformException] on channel failure and
  /// [StateError] if the native side returns a null/absent string (which would
  /// indicate a binding-contract violation).
  Future<String> _invokeString(String method, [Map<String, Object?>? args]) async {
    final result = await _channel.invokeMethod<String>(method, args);
    if (result == null) {
      throw StateError('openidx_engine.$method returned null');
    }
    return result;
  }

  /// Initialize the engine against the app's per-app config directory. The host
  /// passes the OS sandbox path (see `path_provider`). Idempotent on the Go
  /// side — safe to call on every launch. Returns nothing meaningful (the
  /// gomobile `Start` returns only an error), so we ignore the body.
  Future<void> start(String configDir) async {
    await _channel.invokeMethod<void>('start', <String, Object?>{
      'configDir': configDir,
    });
  }

  Future<String> status() => _invokeString('status');

  Future<String> login() => _invokeString('login');

  Future<void> logout() async {
    await _channel.invokeMethod<void>('logout');
  }

  Future<String> enroll(String code) =>
      _invokeString('enroll', <String, Object?>{'code': code});

  Future<String> posture() => _invokeString('posture');

  Future<String> pamList() => _invokeString('pamList');

  Future<String> pamConnect(String entryId) =>
      _invokeString('pamConnect', <String, Object?>{'entryId': entryId});

  Future<void> pamRequest(String entryId, String reason) async {
    await _channel.invokeMethod<void>('pamRequest', <String, Object?>{
      'entryId': entryId,
      'reason': reason,
    });
  }

  Future<String> zitiDial(String service) =>
      _invokeString('zitiDial', <String, Object?>{'service': service});

  Future<void> zitiClose(String service) async {
    await _channel.invokeMethod<void>('zitiClose', <String, Object?>{
      'service': service,
    });
  }

  /// Tail of the on-device control log (engine/control activity). Used by the
  /// in-app log viewer so users can inspect control logs without adb.
  Future<String> logs() => _invokeString('logs');
}
