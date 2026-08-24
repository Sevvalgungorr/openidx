import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../api/api_client.dart';
import '../api/auth.dart';
import '../api/governance.dart';
import '../api/mfa.dart';
import '../api/notifications.dart';
import '../api/token_store.dart';
import '../features/totp.dart';
import 'providers.dart';

/// Riverpod wiring for the mobile-only backend journeys (MFA, governance,
/// notifications, authenticator). These sit alongside the Phase-1 engine
/// providers in `providers.dart`; the engine handles enroll/PAM/Ziti, while
/// these talk HTTP to the backend directly.

/// Secure keystore for tokens + otpauth secrets.
final tokenStoreProvider = Provider<TokenStore>((ref) => SecureTokenStore());

final secureStorageProvider = Provider<FlutterSecureStorage>(
  (ref) => const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  ),
);

/// Base URL for the backend gateway. Derived from live agent status
/// (`server_url`) once enrolled; empty until then.
final backendBaseUrlProvider = Provider<String>((ref) {
  return ref.watch(currentStatusProvider).serverUrl;
});

final apiClientProvider = Provider<ApiClient>((ref) {
  final client = ApiClient(
    baseUrl: ref.watch(backendBaseUrlProvider),
    tokens: ref.watch(tokenStoreProvider),
  );
  ref.onDispose(() {});
  return client;
});

final authServiceProvider = Provider<AuthService>((ref) {
  return AuthService(
    baseUrl: ref.watch(backendBaseUrlProvider),
    tokens: ref.watch(tokenStoreProvider),
  );
});

final mfaApiProvider =
    Provider<MfaApi>((ref) => MfaApi(ref.watch(apiClientProvider)));

final governanceApiProvider =
    Provider<GovernanceApi>((ref) => GovernanceApi(ref.watch(apiClientProvider)));

final notificationsApiProvider = Provider<NotificationsApi>(
    (ref) => NotificationsApi(ref.watch(apiClientProvider)));

// -- Governance / notifications async providers -------------------------------

final myApprovalsProvider = FutureProvider<List<ApprovalItem>>((ref) {
  return ref.watch(governanceApiProvider).myApprovals();
});

final myRequestsProvider = FutureProvider<List<AccessRequest>>((ref) {
  return ref.watch(governanceApiProvider).myRequests();
});

final notificationsProvider = FutureProvider<List<AppNotification>>((ref) {
  return ref.watch(notificationsApiProvider).list();
});

// -- Authenticator (offline TOTP) --------------------------------------------

const _totpStorageKey = 'openidx.totp.accounts';

/// Persists + exposes the offline TOTP accounts. Secrets live in the platform
/// keystore; codes are generated on-device (see `features/totp.dart`).
class AuthenticatorController extends StateNotifier<List<OtpAccount>> {
  AuthenticatorController(this._storage) : super(const []) {
    _load();
  }

  final FlutterSecureStorage _storage;

  Future<void> _load() async {
    final raw = await _storage.read(key: _totpStorageKey);
    if (raw != null && raw.isNotEmpty) {
      state = OtpAccount.decodeList(raw);
    }
  }

  Future<void> _persist() =>
      _storage.write(key: _totpStorageKey, value: OtpAccount.encodeList(state));

  /// Add an account from a pasted/scanned `otpauth://` URI.
  Future<void> addFromUri(String uri) async {
    final account = OtpAccount.parseUri(uri);
    state = [
      ...state.where((a) => a.id != account.id),
      account,
    ];
    await _persist();
  }

  Future<void> remove(String id) async {
    state = state.where((a) => a.id != id).toList();
    await _persist();
  }
}

final authenticatorProvider =
    StateNotifierProvider<AuthenticatorController, List<OtpAccount>>((ref) {
  return AuthenticatorController(ref.watch(secureStorageProvider));
});
