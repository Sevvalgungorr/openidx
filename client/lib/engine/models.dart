/// Data models for the OpenIDX engine control API.
///
/// The JSON tags below MUST match the shapes emitted by the Go
/// `openidx-agent serve` control server exactly. See the ENGINE CONTROL
/// CONTRACT in `client/README.md`.
library;

/// Helpers that tolerate the loose JSON typing that comes off `dart:convert`.
int _asInt(Object? v, [int fallback = 0]) {
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v) ?? fallback;
  return fallback;
}

double _asDouble(Object? v, [double fallback = 0]) {
  if (v is double) return v;
  if (v is num) return v.toDouble();
  if (v is String) return double.tryParse(v) ?? fallback;
  return fallback;
}

bool _asBool(Object? v, [bool fallback = false]) {
  if (v is bool) return v;
  if (v is String) return v.toLowerCase() == 'true';
  if (v is num) return v != 0;
  return fallback;
}

String _asString(Object? v, [String fallback = '']) {
  if (v == null) return fallback;
  if (v is String) return v;
  return v.toString();
}

/// `GET /status`
class AgentStatus {
  const AgentStatus({
    required this.enrolled,
    required this.agentId,
    required this.deviceId,
    required this.serverUrl,
    required this.zitiEnrolled,
    required this.loggedIn,
    required this.userSub,
    required this.userEmail,
    required this.tokenExpiry,
    required this.tokenExpired,
  });

  final bool enrolled;
  final String agentId;
  final String deviceId;
  final String serverUrl;
  final bool zitiEnrolled;
  final bool loggedIn;
  final String userSub;
  final String userEmail;
  final int tokenExpiry;
  final bool tokenExpired;

  factory AgentStatus.fromJson(Map<String, dynamic> json) => AgentStatus(
        enrolled: _asBool(json['enrolled']),
        agentId: _asString(json['agent_id']),
        deviceId: _asString(json['device_id']),
        serverUrl: _asString(json['server_url']),
        zitiEnrolled: _asBool(json['ziti_enrolled']),
        loggedIn: _asBool(json['logged_in']),
        userSub: _asString(json['user_sub']),
        userEmail: _asString(json['user_email']),
        tokenExpiry: _asInt(json['token_expiry']),
        tokenExpired: _asBool(json['token_expired']),
      );

  /// A conservative "not enrolled / not logged in" default used before the
  /// first successful poll so the UI has something to render.
  static const AgentStatus unknown = AgentStatus(
    enrolled: false,
    agentId: '',
    deviceId: '',
    serverUrl: '',
    zitiEnrolled: false,
    loggedIn: false,
    userSub: '',
    userEmail: '',
    tokenExpiry: 0,
    tokenExpired: false,
  );
}

/// `POST /login`
class User {
  const User({required this.sub, required this.email, required this.exp});

  final String sub;
  final String email;
  final int exp;

  factory User.fromJson(Map<String, dynamic> json) => User(
        sub: _asString(json['sub']),
        email: _asString(json['email']),
        exp: _asInt(json['exp']),
      );
}

/// `POST /enroll`
class EnrollResult {
  const EnrollResult({
    required this.agentId,
    required this.deviceId,
    required this.serverUrl,
    required this.zitiIdentity,
  });

  final String agentId;
  final String deviceId;
  final String serverUrl;
  final String zitiIdentity;

  factory EnrollResult.fromJson(Map<String, dynamic> json) => EnrollResult(
        agentId: _asString(json['agent_id']),
        deviceId: _asString(json['device_id']),
        serverUrl: _asString(json['server_url']),
        zitiIdentity: _asString(json['ziti_identity']),
      );
}

/// One row of the posture assessment.
class PostureCheck {
  const PostureCheck({
    required this.type,
    required this.severity,
    required this.status,
    required this.score,
    required this.message,
  });

  final String type;
  final String severity;
  final String status;
  final double score;
  final String message;

  factory PostureCheck.fromJson(Map<String, dynamic> json) => PostureCheck(
        type: _asString(json['type']),
        severity: _asString(json['severity']),
        status: _asString(json['status']),
        score: _asDouble(json['score']),
        message: _asString(json['message']),
      );
}

/// `GET /posture`
class Posture {
  const Posture({
    required this.compliant,
    required this.passed,
    required this.failed,
    required this.warned,
    required this.errored,
    required this.ranAt,
    required this.checks,
  });

  final bool compliant;
  final int passed;
  final int failed;
  final int warned;
  final int errored;
  final String ranAt;
  final List<PostureCheck> checks;

  factory Posture.fromJson(Map<String, dynamic> json) {
    final rawChecks = json['checks'];
    final checks = <PostureCheck>[];
    if (rawChecks is List) {
      for (final c in rawChecks) {
        if (c is Map<String, dynamic>) {
          checks.add(PostureCheck.fromJson(c));
        }
      }
    }
    return Posture(
      compliant: _asBool(json['compliant']),
      passed: _asInt(json['passed']),
      failed: _asInt(json['failed']),
      warned: _asInt(json['warned']),
      errored: _asInt(json['errored']),
      ranAt: _asString(json['ran_at']),
      checks: checks,
    );
  }

  static const Posture empty = Posture(
    compliant: false,
    passed: 0,
    failed: 0,
    warned: 0,
    errored: 0,
    ranAt: '',
    checks: <PostureCheck>[],
  );
}

/// One entry from `GET /pam/entries`.
class PamEntry {
  const PamEntry({
    required this.id,
    required this.name,
    required this.entryType,
    required this.requireApproval,
    required this.recordSession,
    required this.reachMode,
    required this.hostname,
    required this.port,
  });

  final String id;
  final String name;
  final String entryType;
  final bool requireApproval;
  final bool recordSession;
  final String reachMode;
  final String hostname;
  final int port;

  factory PamEntry.fromJson(Map<String, dynamic> json) => PamEntry(
        id: _asString(json['id']),
        name: _asString(json['name']),
        entryType: _asString(json['entry_type']),
        requireApproval: _asBool(json['require_approval']),
        recordSession: _asBool(json['record_session']),
        reachMode: _asString(json['reach_mode']),
        hostname: _asString(json['hostname']),
        port: _asInt(json['port']),
      );
}

/// `POST /pam/connect`
class PamConnectResult {
  const PamConnectResult({
    required this.launchType,
    required this.connectUrl,
    required this.url,
  });

  final String launchType;
  final String connectUrl;
  final String url;

  factory PamConnectResult.fromJson(Map<String, dynamic> json) =>
      PamConnectResult(
        launchType: _asString(json['launch_type']),
        connectUrl: _asString(json['connect_url']),
        url: _asString(json['url']),
      );

  /// Best-effort URL to hand to `url_launcher`: prefer `connect_url`, fall
  /// back to the generic `url` field.
  String get launchTarget => connectUrl.isNotEmpty ? connectUrl : url;
}
