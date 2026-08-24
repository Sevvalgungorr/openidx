import 'api_client.dart';

/// MFA endpoints (identity service): TOTP setup/enroll/status and push
/// register/challenge/verify. Mirrors the RN app's MFA surface.
class MfaApi {
  MfaApi(this._api);
  final ApiClient _api;

  // -- TOTP -------------------------------------------------------------------

  /// `POST /api/v1/identity/mfa/totp/setup` → provisioning secret + otpauth URI.
  Future<TotpSetup> totpSetup() async {
    final json = await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/mfa/totp/setup',
    );
    return TotpSetup.fromJson(json);
  }

  /// `POST /api/v1/identity/mfa/totp/enroll` — confirm setup with a live code.
  Future<void> totpEnroll(String code) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/mfa/totp/enroll',
      data: {'code': code},
    );
  }

  /// `GET /api/v1/identity/mfa/totp/status`.
  Future<MfaStatus> totpStatus() async {
    final json = await _api.get<Map<String, dynamic>>(
      '/api/v1/identity/mfa/totp/status',
    );
    return MfaStatus.fromJson(json);
  }

  // -- Push -------------------------------------------------------------------

  /// `POST /api/v1/identity/mfa/push/register` — register this device's token.
  Future<void> registerPush({
    required String deviceToken,
    required String platform,
  }) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/mfa/push/register',
      data: {'device_token': deviceToken, 'platform': platform},
    );
  }

  /// `GET /api/v1/identity/mfa/push/challenge/{id}` — challenge context for the
  /// number-match approval screen.
  Future<PushChallenge> pushChallenge(String id) async {
    final json = await _api.get<Map<String, dynamic>>(
      '/api/v1/identity/mfa/push/challenge/$id',
    );
    return PushChallenge.fromJson(json);
  }

  /// `POST /api/v1/identity/mfa/push/verify` — approve / deny / report a push.
  Future<void> pushVerify({
    required String challengeId,
    required PushDecision decision,
    int? selectedNumber,
  }) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/mfa/push/verify',
      data: {
        'challenge_id': challengeId,
        'decision': decision.wire,
        if (selectedNumber != null) 'selected_number': selectedNumber,
      },
    );
  }
}

class TotpSetup {
  const TotpSetup({
    required this.secret,
    required this.otpauthUri,
    required this.issuer,
    required this.account,
  });
  final String secret;
  final String otpauthUri;
  final String issuer;
  final String account;

  factory TotpSetup.fromJson(Map<String, dynamic> j) => TotpSetup(
        secret: (j['secret'] ?? '') as String,
        otpauthUri: (j['otpauth_uri'] ?? j['uri'] ?? '') as String,
        issuer: (j['issuer'] ?? 'OpenIDX') as String,
        account: (j['account'] ?? '') as String,
      );
}

class MfaStatus {
  const MfaStatus({required this.enabled, required this.enrolledAt});
  final bool enabled;
  final String enrolledAt;

  factory MfaStatus.fromJson(Map<String, dynamic> j) => MfaStatus(
        enabled: (j['enabled'] ?? false) as bool,
        enrolledAt: (j['enrolled_at'] ?? '') as String,
      );
}

class PushChallenge {
  const PushChallenge({
    required this.id,
    required this.appName,
    required this.location,
    required this.ipAddress,
    required this.requestedAt,
    required this.numbers,
    required this.correctNumber,
  });
  final String id;
  final String appName;
  final String location;
  final String ipAddress;
  final String requestedAt;

  /// The three numbers shown to the user; one matches [correctNumber].
  final List<int> numbers;
  final int correctNumber;

  factory PushChallenge.fromJson(Map<String, dynamic> j) {
    final raw = j['numbers'];
    final numbers = <int>[];
    if (raw is List) {
      for (final n in raw) {
        if (n is int) {
          numbers.add(n);
        } else if (n is num) {
          numbers.add(n.toInt());
        }
      }
    }
    return PushChallenge(
      id: (j['id'] ?? j['challenge_id'] ?? '') as String,
      appName: (j['app_name'] ?? j['application'] ?? '') as String,
      location: (j['location'] ?? '') as String,
      ipAddress: (j['ip_address'] ?? '') as String,
      requestedAt: (j['requested_at'] ?? '') as String,
      numbers: numbers,
      correctNumber: _asInt(j['correct_number']),
    );
  }
}

enum PushDecision {
  approve('approve'),
  deny('deny'),
  report('report');

  const PushDecision(this.wire);
  final String wire;
}

int _asInt(Object? v) {
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v) ?? -1;
  return -1;
}
