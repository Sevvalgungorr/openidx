import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../engine/engine_client.dart';
import '../engine/engine_supervisor.dart';
import '../engine/models.dart';

/// The active [EngineSupervisor]. Overridden at app boot in `main.dart` with a
/// supervisor that has already spawned/attached the engine.
final engineSupervisorProvider = Provider<EngineSupervisor>((ref) {
  throw UnimplementedError(
    'engineSupervisorProvider must be overridden in ProviderScope',
  );
});

/// The [EngineClient] the UI talks to.
final engineClientProvider = Provider<EngineClient>((ref) {
  return ref.watch(engineSupervisorProvider).client;
});

/// How often to re-poll `/status`.
const _statusPollInterval = Duration(seconds: 5);

/// Streams agent status, re-polling on an interval. Emits the last known good
/// value across transient failures so the UI does not flap.
final statusProvider = StreamProvider<AgentStatus>((ref) async* {
  final engine = ref.watch(engineClientProvider);
  AgentStatus? last;
  while (true) {
    try {
      last = await engine.status();
      yield last;
    } on EngineException {
      if (last != null) {
        yield last;
      } else {
        yield AgentStatus.unknown;
      }
    }
    await Future<void>.delayed(_statusPollInterval);
  }
});

/// Convenience: the current status value (or [AgentStatus.unknown]).
final currentStatusProvider = Provider<AgentStatus>((ref) {
  return ref.watch(statusProvider).valueOrNull ?? AgentStatus.unknown;
});

/// Device posture. Auto-refreshes whenever status changes.
final postureProvider = FutureProvider<Posture>((ref) async {
  // Recompute posture when enrollment/login state flips.
  ref.watch(currentStatusProvider);
  final engine = ref.watch(engineClientProvider);
  return engine.posture();
});

/// PAM entries available to the signed-in user.
final pamEntriesProvider = FutureProvider<List<PamEntry>>((ref) async {
  final status = ref.watch(currentStatusProvider);
  if (!status.loggedIn) return const <PamEntry>[];
  final engine = ref.watch(engineClientProvider);
  return engine.pamList();
});

/// Imperative actions surfaced to the UI. Refreshes derived providers after
/// mutating engine state.
final engineActionsProvider = Provider<EngineActions>((ref) {
  return EngineActions(ref);
});

class EngineActions {
  EngineActions(this._ref);

  final Ref _ref;

  EngineClient get _engine => _ref.read(engineClientProvider);

  Future<void> _refreshAll() async {
    _ref.invalidate(statusProvider);
    _ref.invalidate(postureProvider);
    _ref.invalidate(pamEntriesProvider);
  }

  Future<User> login() async {
    final user = await _engine.login();
    await _refreshAll();
    return user;
  }

  Future<void> logout() async {
    await _engine.logout();
    await _refreshAll();
  }

  Future<EnrollResult> enroll(String code) async {
    final result = await _engine.enroll(code);
    await _refreshAll();
    return result;
  }

  Future<PamConnectResult> pamConnect(String entryId) =>
      _engine.pamConnect(entryId);

  Future<void> pamRequest(String entryId, String reason) =>
      _engine.pamRequest(entryId, reason);
}
