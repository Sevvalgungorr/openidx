import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:openidx_engine/openidx_engine.dart';
import 'package:path_provider/path_provider.dart';

import 'engine_client.dart';
import 'models.dart';

/// [EngineClient] backed by the in-process Go engine on iOS/Android.
///
/// Where [DesktopEngineClient] speaks HTTP over a control socket, this wraps
/// the `openidx_engine` plugin (a `MethodChannel` fronting the gomobile
/// binding). The gomobile funcs return the **same JSON shapes** the control
/// server emits, so we decode with the identical Phase-1 `models.dart`
/// factories — the two clients stay wire-compatible by construction.
///
/// The engine must be started once with a config dir (the OS app-support
/// sandbox); [status] and every other call lazily ensures that has happened.
class MobileEngineClient implements EngineClient {
  MobileEngineClient({OpenidxEngine? engine})
      : _engine = engine ?? OpenidxEngine();

  final OpenidxEngine _engine;

  Future<void>? _started;

  /// Idempotently start the engine against the app-support directory. The Go
  /// side is also idempotent, but we guard here to avoid redundant channel
  /// round-trips and to resolve the sandbox path only once.
  Future<void> _ensureStarted() {
    return _started ??= _guard(() async {
      final dir = await getApplicationSupportDirectory();
      await _engine.start(dir.path);
    }, 'start');
  }

  /// Run [body], converting channel/plugin failures into [EngineException] so
  /// callers see the same error type as the desktop transport.
  Future<T> _guard<T>(Future<T> Function() body, String op) async {
    try {
      return await body();
    } on PlatformException catch (e) {
      throw EngineException(0, e.message ?? 'engine channel error ($op)');
    } on MissingPluginException {
      throw EngineException(
          0, 'openidx_engine plugin not available (op: $op)');
    } on TimeoutException {
      throw EngineException(0, 'timed out calling engine ($op)');
    } on StateError catch (e) {
      throw EngineException(0, e.message);
    }
  }

  /// Decode a JSON object string into a `Map`, or throw [EngineException].
  Map<String, dynamic> _decodeMap(String json, String route) {
    final decoded = _decode(json, route);
    if (decoded is Map<String, dynamic>) return decoded;
    throw EngineException(0, 'unexpected response shape from $route');
  }

  dynamic _decode(String json, String route) {
    try {
      return jsonDecode(json);
    } on FormatException catch (e) {
      throw EngineException(0, 'malformed JSON from $route: ${e.message}');
    }
  }

  @override
  Future<AgentStatus> status() async {
    await _ensureStarted();
    final json = await _guard(_engine.status, 'status');
    return AgentStatus.fromJson(_decodeMap(json, 'status'));
  }

  @override
  Future<User> login() async {
    await _ensureStarted();
    final json = await _guard(_engine.login, 'login');
    return User.fromJson(_decodeMap(json, 'login'));
  }

  @override
  Future<void> logout() async {
    await _ensureStarted();
    await _guard(_engine.logout, 'logout');
  }

  @override
  Future<EnrollResult> enroll(String code) async {
    await _ensureStarted();
    final json = await _guard(() => _engine.enroll(code), 'enroll');
    return EnrollResult.fromJson(_decodeMap(json, 'enroll'));
  }

  @override
  Future<Posture> posture() async {
    await _ensureStarted();
    final json = await _guard(_engine.posture, 'posture');
    return Posture.fromJson(_decodeMap(json, 'posture'));
  }

  @override
  Future<List<PamEntry>> pamList() async {
    await _ensureStarted();
    final json = await _guard(_engine.pamList, 'pamList');
    final decoded = _decode(json, 'pamList');
    if (decoded is! List) {
      throw const EngineException(0, 'unexpected response shape from pamList');
    }
    return decoded
        .whereType<Map<String, dynamic>>()
        .map(PamEntry.fromJson)
        .toList(growable: false);
  }

  @override
  Future<PamConnectResult> pamConnect(String entryId) async {
    await _ensureStarted();
    final json = await _guard(() => _engine.pamConnect(entryId), 'pamConnect');
    return PamConnectResult.fromJson(_decodeMap(json, 'pamConnect'));
  }

  @override
  Future<void> pamRequest(String entryId, String reason) async {
    await _ensureStarted();
    await _guard(() => _engine.pamRequest(entryId, reason), 'pamRequest');
  }

  @override
  Future<String> zitiDial(String service) async {
    await _ensureStarted();
    final json = await _guard(() => _engine.zitiDial(service), 'zitiDial');
    final map = _decodeMap(json, 'zitiDial');
    final addr = map['addr'] ?? map['url'] ?? map['local_addr'];
    return addr is String ? addr : '';
  }

  @override
  Future<void> zitiClose(String service) async {
    await _ensureStarted();
    await _guard(() => _engine.zitiClose(service), 'zitiClose');
  }

  @override
  void close() {
    // The in-process engine lives for the app's lifetime; nothing to release.
  }
}
