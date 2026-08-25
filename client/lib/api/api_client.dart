import 'package:dio/dio.dart';

import 'token_store.dart';

/// Thrown for non-2xx backend responses that the caller should surface.
class ApiException implements Exception {
  const ApiException(this.status, this.message);
  final int status;
  final String message;
  @override
  String toString() => 'ApiException($status): $message';
}

/// Token-authed HTTP client for the OpenIDX backend — the Dart analogue of the
/// React-Native app's `src/lib/api.ts`.
///
/// - Base URL is the gateway (from [AgentStatus.serverUrl] or an explicit
///   config), under which every service is reachable.
/// - A request interceptor injects `Authorization: Bearer <access>` and an
///   optional `X-Org-Slug`.
/// - A response interceptor refreshes **once** on 401 via `/oauth/token`
///   (single-flight), retries the original request, and on a second failure
///   clears tokens and notifies [onAuthLost].
///
/// The engine journeys (status/enroll/PAM/Ziti) go through [EngineClient];
/// this client is for the *non-engine* journeys (MFA, governance,
/// notifications) that talk HTTP directly.
///
/// ## Token source
/// On **mobile** the user signs in through the in-process Go engine (deep-link
/// OAuth), so the session tokens live in the engine's store — NOT in this
/// client's [TokenStore], which stays empty. Passing [engineTokenGetter] makes
/// the engine the single source of truth: the request interceptor fetches the
/// Bearer token from the engine (which also refreshes it transparently) on every
/// call. When no getter is supplied (e.g. desktop / tests) it falls back to the
/// [TokenStore] path, preserving the original behavior.
typedef EngineTokenGetter = Future<String> Function();

class ApiClient {
  ApiClient({
    required String baseUrl,
    required TokenStore tokens,
    Dio? dio,
    this.onAuthLost,
    this.engineTokenGetter,
  })  : _tokens = tokens,
        _dio = dio ?? Dio() {
    _dio.options
      ..baseUrl = baseUrl
      ..connectTimeout = const Duration(seconds: 20)
      ..receiveTimeout = const Duration(seconds: 20)
      ..headers['Accept'] = 'application/json';
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: _onRequest,
        onError: _onError,
      ),
    );
  }

  final Dio _dio;
  final TokenStore _tokens;

  /// Invoked when a hard 401 (or a failed refresh) means the session is gone;
  /// the auth layer routes back to sign-in.
  final void Function()? onAuthLost;

  /// When set, the primary Bearer token source: fetched from the engine (which
  /// owns the session and refreshes it) on every request. Falls back to the
  /// [TokenStore] when null.
  final EngineTokenGetter? engineTokenGetter;

  Dio get raw => _dio;

  void setBaseUrl(String baseUrl) => _dio.options.baseUrl = baseUrl;

  /// Resolves the access token, preferring the engine (mobile) over the local
  /// token store. Returns null when not signed in / unavailable.
  Future<String?> _accessToken() async {
    final getter = engineTokenGetter;
    if (getter != null) {
      try {
        final t = await getter();
        if (t.isNotEmpty) return t;
      } catch (_) {
        // "not signed in" (or a channel hiccup): fall through so no header is
        // sent and the screen shows its empty/401 state rather than crashing.
      }
      return null;
    }
    return _tokens.accessToken();
  }

  Future<void> _onRequest(
      RequestOptions options, RequestInterceptorHandler handler) async {
    final token = await _accessToken();
    if (token != null && token.isNotEmpty) {
      options.headers['Authorization'] = 'Bearer $token';
    }
    final org = await _tokens.orgSlug();
    if (org != null && org.isNotEmpty) {
      options.headers['X-Org-Slug'] = org;
    }
    handler.next(options);
  }

  Future<bool>? _refreshing;

  /// Single-flight refresh: concurrent 401s share one `/oauth/token` call.
  Future<bool> _tryRefresh() {
    return _refreshing ??= () async {
      try {
        final rt = await _tokens.refreshToken();
        if (rt == null || rt.isEmpty) return false;
        final resp = await Dio(BaseOptions(baseUrl: _dio.options.baseUrl))
            .post<Map<String, dynamic>>(
          '/oauth/token',
          data: {
            'grant_type': 'refresh_token',
            'refresh_token': rt,
          },
          options: Options(contentType: Headers.jsonContentType),
        );
        final data = resp.data;
        if (data == null) return false;
        await _tokens.save(
          access: data['access_token'] as String?,
          refresh: data['refresh_token'] as String? ?? rt,
        );
        return true;
      } catch (_) {
        return false;
      } finally {
        _refreshing = null;
      }
    }();
  }

  Future<void> _onError(
      DioException err, ErrorInterceptorHandler handler) async {
    final response = err.response;
    final original = err.requestOptions;
    final alreadyRetried = original.extra['_retried'] == true;

    if (response?.statusCode == 401 && !alreadyRetried) {
      if (engineTokenGetter != null) {
        // The engine owns (and refreshes) the session: re-fetch — this triggers
        // a transparent refresh on the Go side — and retry once. A still-401
        // means the session is genuinely gone.
        final token = await _accessToken();
        if (token != null && token.isNotEmpty) {
          original.extra['_retried'] = true;
          original.headers['Authorization'] = 'Bearer $token';
          try {
            final retry = await _dio.fetch<dynamic>(original);
            return handler.resolve(retry);
          } on DioException catch (e) {
            onAuthLost?.call();
            return handler.next(e);
          }
        }
        onAuthLost?.call();
      } else if (await _tryRefresh()) {
        original.extra['_retried'] = true;
        final token = await _tokens.accessToken();
        if (token != null) {
          original.headers['Authorization'] = 'Bearer $token';
        }
        try {
          final retry = await _dio.fetch<dynamic>(original);
          return handler.resolve(retry);
        } on DioException catch (e) {
          return handler.next(e);
        }
      } else {
        await _tokens.clear();
        onAuthLost?.call();
      }
    }
    handler.next(err);
  }

  // -- Convenience surface (mirrors the RN `api.get/post/...`). ---------------

  Future<T> get<T>(String path, {Map<String, dynamic>? query}) =>
      _unwrap<T>(_dio.get<T>(path, queryParameters: query));

  Future<T> post<T>(String path, {Object? data}) =>
      _unwrap<T>(_dio.post<T>(path, data: data));

  Future<T> put<T>(String path, {Object? data}) =>
      _unwrap<T>(_dio.put<T>(path, data: data));

  Future<T> delete<T>(String path, {Object? data}) =>
      _unwrap<T>(_dio.delete<T>(path, data: data));

  Future<T> _unwrap<T>(Future<Response<T>> future) async {
    try {
      final resp = await future;
      return resp.data as T;
    } on DioException catch (e) {
      final status = e.response?.statusCode ?? 0;
      throw ApiException(status, _messageOf(e));
    }
  }

  String _messageOf(DioException e) {
    final data = e.response?.data;
    if (data is Map && data['error'] is String) return data['error'] as String;
    if (data is Map && data['message'] is String) {
      return data['message'] as String;
    }
    return e.message ?? 'request failed';
  }
}
