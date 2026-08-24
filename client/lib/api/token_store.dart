import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Persists OAuth tokens (and the tenant org slug) in the platform keystore /
/// keychain via `flutter_secure_storage`.
///
/// Kept as a tiny interface so tests can substitute an in-memory fake without a
/// platform channel.
abstract class TokenStore {
  Future<String?> accessToken();
  Future<String?> refreshToken();
  Future<String?> orgSlug();

  Future<void> save({String? access, String? refresh, String? orgSlug});
  Future<void> clear();
}

/// Default [TokenStore] backed by `flutter_secure_storage` (Keychain on iOS,
/// EncryptedSharedPreferences / Keystore on Android).
class SecureTokenStore implements TokenStore {
  SecureTokenStore({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            );

  final FlutterSecureStorage _storage;

  static const _kAccess = 'openidx.access_token';
  static const _kRefresh = 'openidx.refresh_token';
  static const _kOrg = 'openidx.org_slug';

  @override
  Future<String?> accessToken() => _storage.read(key: _kAccess);

  @override
  Future<String?> refreshToken() => _storage.read(key: _kRefresh);

  @override
  Future<String?> orgSlug() => _storage.read(key: _kOrg);

  @override
  Future<void> save({String? access, String? refresh, String? orgSlug}) async {
    if (access != null) await _storage.write(key: _kAccess, value: access);
    if (refresh != null) await _storage.write(key: _kRefresh, value: refresh);
    if (orgSlug != null) await _storage.write(key: _kOrg, value: orgSlug);
  }

  @override
  Future<void> clear() async {
    await _storage.delete(key: _kAccess);
    await _storage.delete(key: _kRefresh);
  }
}
