import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';

import 'token_store.dart';

/// Mobile authentication for the OpenIDX backend — the Dart analogue of the
/// React-Native app's `src/lib/auth.tsx` + `oauth.ts`.
///
/// Flow (native-first, browser fallback):
///  1. `POST /oauth/native/login-init` (with a PKCE code_challenge) →
///     `{ login_session }`.
///  2. Prefer **passkey**: `POST /oauth/passkey-begin` → WebAuthn options,
///     the platform authenticator signs, `POST /oauth/passkey-finish` →
///     `{ code }`. If no passkey / user cancels, fall back to the browser
///     Authorization-Code + PKCE flow (opened via a deep link; the callback
///     `openidx://oauth-callback?code=…` is handled by `deep_links.dart`).
///  3. Exchange the `code` at `/oauth/token` (with the PKCE `code_verifier`)
///     for tokens, stored in [TokenStore].
///
/// The heavy WebAuthn ceremony (assertion signing) is a platform concern; this
/// module exposes seams ([passkeyAssertion], [browserAuthorize]) the app wires
/// to `local_auth`/a WebAuthn plugin and `app_links`. Defaults are TODO stubs
/// so the flow is testable end-to-end at the HTTP layer.
class AuthService {
  AuthService({
    required this.baseUrl,
    required TokenStore tokens,
    Dio? dio,
    this.clientId = 'openidx-mobile',
    this.redirectUri = 'openidx://oauth-callback',
    Future<Map<String, dynamic>> Function(Map<String, dynamic> options)?
        passkeyAssertion,
    Future<String> Function(Uri authorizeUrl)? browserAuthorize,
  })  : _tokens = tokens,
        _dio = dio ?? Dio(BaseOptions(baseUrl: baseUrl)),
        _passkeyAssertion = passkeyAssertion,
        _browserAuthorize = browserAuthorize;

  final String baseUrl;
  final String clientId;
  final String redirectUri;
  final TokenStore _tokens;
  final Dio _dio;

  final Future<Map<String, dynamic>> Function(Map<String, dynamic>)?
      _passkeyAssertion;
  final Future<String> Function(Uri)? _browserAuthorize;

  final _rng = Random.secure();

  /// Sign in. Returns once tokens are persisted in [TokenStore].
  ///
  /// [preferPasskey] tries the native passkey path first; on failure it falls
  /// back to the browser PKCE flow.
  Future<void> signIn({bool preferPasskey = true}) async {
    final verifier = _codeVerifier();
    final challenge = _codeChallenge(verifier);

    final loginSession = await _loginInit(challenge);

    String? code;
    if (preferPasskey) {
      code = await _tryPasskey(loginSession);
    }
    code ??= await _browserFallback(verifier, challenge, loginSession);

    await _exchange(code, verifier);
  }

  Future<void> signOut() => _tokens.clear();

  /// Current access token (may be expired; the [ApiClient] refreshes lazily).
  Future<String?> token() => _tokens.accessToken();

  Future<bool> isSignedIn() async {
    final t = await _tokens.accessToken();
    return t != null && t.isNotEmpty;
  }

  // -- Steps ------------------------------------------------------------------

  /// `POST /oauth/native/login-init` → `{ login_session }`.
  Future<String> _loginInit(String codeChallenge) async {
    final resp = await _dio.post<Map<String, dynamic>>(
      '/oauth/native/login-init',
      data: {
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'code_challenge': codeChallenge,
        'code_challenge_method': 'S256',
        'scope': 'openid profile email offline_access',
      },
      options: Options(contentType: Headers.jsonContentType),
    );
    final session = resp.data?['login_session'];
    if (session is! String || session.isEmpty) {
      throw StateError('login-init did not return a login_session');
    }
    return session;
  }

  /// Passkey path: begin → assert (platform) → finish → `{ code }`.
  /// Returns null on any failure/cancel so the caller can fall back.
  Future<String?> _tryPasskey(String loginSession) async {
    final assertFn = _passkeyAssertion;
    if (assertFn == null) return null;
    try {
      final begin = await _dio.post<Map<String, dynamic>>(
        '/oauth/passkey-begin',
        data: {'login_session': loginSession},
        options: Options(contentType: Headers.jsonContentType),
      );
      final options = begin.data ?? const <String, dynamic>{};
      final assertion = await assertFn(options);
      final finish = await _dio.post<Map<String, dynamic>>(
        '/oauth/passkey-finish',
        data: {
          'login_session': loginSession,
          'assertion': assertion,
        },
        options: Options(contentType: Headers.jsonContentType),
      );
      final code = finish.data?['code'];
      return code is String && code.isNotEmpty ? code : null;
    } catch (_) {
      return null; // fall back to the browser flow.
    }
  }

  /// Browser Authorization-Code + PKCE fallback. Opens the hosted login and
  /// waits for the `openidx://oauth-callback?code=…` deep link.
  Future<String> _browserFallback(
      String verifier, String challenge, String loginSession) async {
    final openFn = _browserAuthorize;
    if (openFn == null) {
      throw StateError(
          'no passkey and no browserAuthorize handler configured');
    }
    final authorize = Uri.parse('$baseUrl/oauth/authorize').replace(
      queryParameters: {
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'response_type': 'code',
        'scope': 'openid profile email offline_access',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'login_session': loginSession,
      },
    );
    final callback = await openFn(authorize);
    // The handler may hand back the full callback URL or the bare code.
    final parsed = Uri.tryParse(callback);
    final code = parsed?.queryParameters['code'] ?? callback;
    if (code.isEmpty) throw StateError('oauth callback missing code');
    return code;
  }

  /// Exchange the authorization code for tokens and persist them.
  Future<void> _exchange(String code, String verifier) async {
    final resp = await _dio.post<Map<String, dynamic>>(
      '/oauth/token',
      data: {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'code_verifier': verifier,
      },
      options: Options(contentType: Headers.jsonContentType),
    );
    final data = resp.data;
    final access = data?['access_token'];
    if (access is! String || access.isEmpty) {
      throw StateError('token endpoint returned no access_token');
    }
    await _tokens.save(
      access: access,
      refresh: data?['refresh_token'] as String?,
    );
  }

  // -- PKCE helpers -----------------------------------------------------------

  String _codeVerifier() {
    final bytes = List<int>.generate(64, (_) => _rng.nextInt(256));
    return _base64Url(bytes);
  }

  String _codeChallenge(String verifier) =>
      _base64Url(sha256.convert(utf8.encode(verifier)).bytes);

  String _base64Url(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');
}
