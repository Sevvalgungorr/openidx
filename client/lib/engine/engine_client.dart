import 'models.dart';

/// Thrown when the engine returns a non-2xx response.
class EngineException implements Exception {
  const EngineException(this.status, this.message);

  /// HTTP status code from the control server (or a synthetic code such as
  /// `0` when the socket could not be reached).
  final int status;
  final String message;

  @override
  String toString() => 'EngineException($status): $message';
}

/// Transport-agnostic contract for talking to the local `openidx-agent`
/// control server. The desktop implementation lives in
/// `desktop_engine_client.dart`; tests supply a loopback-HTTP fake.
abstract class EngineClient {
  Future<AgentStatus> status();

  Future<User> login();

  Future<void> logout();

  /// Enrolls this device with a one-time [code]. On mobile (no seeded config)
  /// [serverUrl] must be supplied so the engine knows which server to target;
  /// desktop resolves it from the installed sidecar config and ignores it.
  Future<EnrollResult> enroll(String code, {String? serverUrl});

  Future<Posture> posture();

  Future<List<PamEntry>> pamList();

  Future<PamConnectResult> pamConnect(String entryId);

  Future<void> pamRequest(String entryId, String reason);

  /// Dials a Ziti service; returns the local address the tunnel is bound to.
  Future<String> zitiDial(String service);

  Future<void> zitiClose(String service);

  /// Release any pooled connections. No-op for stateless implementations.
  void close() {}
}
