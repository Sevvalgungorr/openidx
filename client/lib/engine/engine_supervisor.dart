import 'dart:async';
import 'dart:io';

import 'desktop_engine_client.dart';
import 'engine_client.dart';

/// Owns the lifecycle of the local `openidx-agent serve` process.
///
/// Two modes:
///  * **spawn** — this app launched the engine and should stop it on exit
///    (dev / standalone install).
///  * **attach** — a system service (systemd / launchd / Windows Service)
///    already runs the engine; we only connect to it.
class EngineSupervisor {
  EngineSupervisor({
    EngineClient? client,
    Duration readyTimeout = const Duration(seconds: 20),
    Duration pollInterval = const Duration(milliseconds: 400),
  })  : _client = client ?? DesktopEngineClient(),
        _readyTimeout = readyTimeout,
        _pollInterval = pollInterval;

  final EngineClient _client;
  final Duration _readyTimeout;
  final Duration _pollInterval;

  Process? _process;
  bool _attached = false;

  EngineClient get client => _client;

  /// True if we spawned the engine ourselves and thus own its shutdown.
  bool get owns => _process != null;

  /// The executable name (platform-suffixed).
  static String get _binaryName =>
      Platform.isWindows ? 'openidx-agent.exe' : 'openidx-agent';

  /// Candidate locations for the sidecar binary, in priority order:
  ///  1. `OPENIDX_AGENT_BIN` env override.
  ///  2. Bundled next to the running app executable (packaged install).
  ///  3. A conventional `bin/` sibling directory.
  ///  4. On PATH (resolved by [Process.start] when we pass a bare name).
  List<String> candidatePaths() {
    final candidates = <String>[];

    final override = Platform.environment['OPENIDX_AGENT_BIN'];
    if (override != null && override.isNotEmpty) {
      candidates.add(override);
    }

    final exeDir = File(Platform.resolvedExecutable).parent.path;
    final sep = Platform.pathSeparator;
    candidates
      ..add('$exeDir$sep$_binaryName')
      ..add('$exeDir${sep}bin$sep$_binaryName');

    // Bare name → resolved via PATH by the OS.
    candidates.add(_binaryName);
    return candidates;
  }

  String _resolveBinary() {
    for (final c in candidatePaths()) {
      // A bare name (no separator) is deferred to PATH resolution.
      if (!c.contains(Platform.pathSeparator)) return c;
      if (File(c).existsSync()) return c;
    }
    return _binaryName; // last-resort: let the OS try PATH.
  }

  /// Ensure the engine is reachable: if `/status` already answers, [attach];
  /// otherwise [spawn] it. Returns once the engine is ready.
  Future<EngineClient> start() async {
    if (await _reachable()) {
      _attached = true;
      return _client;
    }
    await spawn();
    await waitReady();
    return _client;
  }

  /// Connect to an already-running engine (system service) without spawning.
  Future<EngineClient> attach() async {
    _attached = true;
    await waitReady();
    return _client;
  }

  /// Launch `openidx-agent serve` as a detached child process.
  Future<void> spawn() async {
    final bin = _resolveBinary();
    _process = await Process.start(
      bin,
      const ['serve'],
      mode: ProcessStartMode.detachedWithStdio,
    );
  }

  /// Poll `/status` until the engine answers or the timeout elapses.
  Future<void> waitReady() async {
    final deadline = DateTime.now().add(_readyTimeout);
    while (DateTime.now().isBefore(deadline)) {
      if (await _reachable()) return;
      await Future<void>.delayed(_pollInterval);
    }
    throw EngineException(
      0,
      'openidx-agent did not become ready within '
      '${_readyTimeout.inSeconds}s',
    );
  }

  Future<bool> _reachable() async {
    try {
      await _client.status();
      return true;
    } on Object {
      return false;
    }
  }

  /// Stop the engine if (and only if) we spawned it. Attached services are
  /// left running.
  Future<void> dispose() async {
    _client.close();
    if (_attached) return;
    final proc = _process;
    if (proc != null) {
      proc.kill(ProcessSignal.sigterm);
      _process = null;
    }
  }
}
