import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'engine_client.dart';
import 'models.dart';

/// Describes where and how to reach the local control server.
///
/// Two flavours:
///  * [EngineEndpoint.unixSocket] — non-Windows: an HTTP/1.1 server bound to a
///    Unix-domain socket. No auth token; the socket's filesystem permissions
///    are the trust boundary.
///  * [EngineEndpoint.tcp] — Windows: a loopback TCP server whose address and
///    bearer token are published in
///    `%ProgramData%\OpenIDX\agent\control-endpoint.json`.
class EngineEndpoint {
  const EngineEndpoint._({
    required this.isUnixSocket,
    this.socketPath,
    this.host,
    this.port,
    this.token,
  });

  factory EngineEndpoint.unixSocket(String path) =>
      EngineEndpoint._(isUnixSocket: true, socketPath: path);

  factory EngineEndpoint.tcp({
    required String host,
    required int port,
    required String token,
  }) =>
      EngineEndpoint._(
        isUnixSocket: false,
        host: host,
        port: port,
        token: token,
      );

  final bool isUnixSocket;
  final String? socketPath;
  final String? host;
  final int? port;
  final String? token;
}

/// Resolves the control endpoint for the current platform.
class EngineEndpointResolver {
  const EngineEndpointResolver();

  /// The fixed socket file name used on POSIX platforms.
  static const String socketName = 'openidx-agent.sock';

  /// Non-Windows socket path: `${XDG_RUNTIME_DIR:-<tmpdir>}/openidx-agent.sock`.
  String unixSocketPath() {
    final runtimeDir = Platform.environment['XDG_RUNTIME_DIR'];
    final base = (runtimeDir != null && runtimeDir.isNotEmpty)
        ? runtimeDir
        : Directory.systemTemp.path;
    return '$base${Platform.pathSeparator}$socketName';
  }

  /// Windows endpoint file:
  /// `%ProgramData%\OpenIDX\agent\control-endpoint.json`.
  File windowsEndpointFile() {
    final programData =
        Platform.environment['ProgramData'] ?? r'C:\ProgramData';
    return File('$programData\\OpenIDX\\agent\\control-endpoint.json');
  }

  /// Discover the current endpoint. On Windows this reads (and validates) the
  /// endpoint file; otherwise it returns the well-known UDS path.
  Future<EngineEndpoint> resolve() async {
    if (Platform.isWindows) {
      final file = windowsEndpointFile();
      if (!await file.exists()) {
        throw EngineException(
          0,
          'control endpoint file not found: ${file.path} '
          '(is openidx-agent running?)',
        );
      }
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! Map<String, dynamic>) {
        throw const EngineException(0, 'malformed control-endpoint.json');
      }
      final addr = (decoded['addr'] as String?) ?? '';
      final token = (decoded['token'] as String?) ?? '';
      final sep = addr.lastIndexOf(':');
      if (sep <= 0 || token.isEmpty) {
        throw const EngineException(0, 'invalid control-endpoint.json contents');
      }
      final host = addr.substring(0, sep);
      final port = int.tryParse(addr.substring(sep + 1)) ?? 0;
      if (port == 0) {
        throw EngineException(0, 'invalid control endpoint port in "$addr"');
      }
      return EngineEndpoint.tcp(host: host, port: port, token: token);
    }
    return EngineEndpoint.unixSocket(unixSocketPath());
  }
}

/// Concrete [EngineClient] speaking HTTP/1.1 to the local control server.
///
/// On non-Windows we install a `connectionFactory` on [HttpClient] that dials
/// the Unix-domain socket, so we get full HTTP semantics (headers, status,
/// chunked bodies) over the UDS for free. On Windows we dial the loopback TCP
/// address and attach `Authorization: Bearer <token>` to every request.
class DesktopEngineClient implements EngineClient {
  DesktopEngineClient({
    EngineEndpointResolver? resolver,
    Duration timeout = const Duration(seconds: 15),
  })  : _resolver = resolver ?? const EngineEndpointResolver(),
        _timeout = timeout;

  /// Test/override seam: construct directly against a known endpoint,
  /// bypassing platform discovery (used by loopback-HTTP tests).
  DesktopEngineClient.forEndpoint(
    EngineEndpoint endpoint, {
    Duration timeout = const Duration(seconds: 15),
  })  : _resolver = const EngineEndpointResolver(),
        _timeout = timeout,
        _endpoint = endpoint;

  final EngineEndpointResolver _resolver;
  final Duration _timeout;

  EngineEndpoint? _endpoint;
  HttpClient? _http;

  Future<EngineEndpoint> _endpointOrResolve() async =>
      _endpoint ??= await _resolver.resolve();

  Future<HttpClient> _clientFor(EngineEndpoint endpoint) async {
    if (_http != null) return _http!;
    final client = HttpClient()..connectionTimeout = _timeout;
    if (endpoint.isUnixSocket) {
      final path = endpoint.socketPath!;
      // Route every connection over the Unix-domain socket regardless of the
      // (dummy) host/port we put in the request URI.
      client.connectionFactory = (uri, proxyHost, proxyPort) {
        final address =
            InternetAddress(path, type: InternetAddressType.unix);
        return Socket.startConnect(address, 0);
      };
    }
    return _http = client;
  }

  /// The URI base. For UDS we use a placeholder authority ("localhost") that
  /// the connectionFactory ignores; for TCP we use the real host:port.
  Uri _uriFor(EngineEndpoint endpoint, String path) {
    if (endpoint.isUnixSocket) {
      return Uri.parse('http://localhost$path');
    }
    return Uri.parse('http://${endpoint.host}:${endpoint.port}$path');
  }

  /// Perform a request and decode the JSON body.
  ///
  /// Throws [EngineException] on transport failure or any non-2xx response.
  Future<dynamic> _send(String method, String path, [Map<String, dynamic>? body]) async {
    final endpoint = await _endpointOrResolve();
    final client = await _clientFor(endpoint);
    final uri = _uriFor(endpoint, path);

    HttpClientRequest request;
    try {
      request = await client.openUrl(method, uri).timeout(_timeout);
    } on TimeoutException {
      throw EngineException(0, 'timed out connecting to engine at $path');
    } on SocketException catch (e) {
      throw EngineException(0, 'cannot reach engine ($path): ${e.message}');
    }

    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (!endpoint.isUnixSocket && endpoint.token != null) {
      request.headers.set(HttpHeaders.authorizationHeader,
          'Bearer ${endpoint.token}');
    }
    if (body != null) {
      final encoded = utf8.encode(jsonEncode(body));
      request.headers.contentType = ContentType.json;
      request.headers.contentLength = encoded.length;
      request.add(encoded);
    }

    final response = await request.close().timeout(_timeout);
    final text = await response.transform(utf8.decoder).join();

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw EngineException(response.statusCode, _errorMessage(text, response));
    }
    if (text.trim().isEmpty) return null;
    return jsonDecode(text);
  }

  String _errorMessage(String text, HttpClientResponse response) {
    if (text.isNotEmpty) {
      try {
        final decoded = jsonDecode(text);
        if (decoded is Map && decoded['error'] is String) {
          return decoded['error'] as String;
        }
      } on FormatException {
        // Non-JSON body; fall through to raw text.
      }
      return text.length > 500 ? text.substring(0, 500) : text;
    }
    return 'HTTP ${response.statusCode}';
  }

  Map<String, dynamic> _asMap(dynamic v, String route) {
    if (v is Map<String, dynamic>) return v;
    throw EngineException(0, 'unexpected response shape from $route');
  }

  @override
  Future<AgentStatus> status() async =>
      AgentStatus.fromJson(_asMap(await _send('GET', '/status'), '/status'));

  @override
  Future<User> login() async =>
      User.fromJson(_asMap(await _send('POST', '/login'), '/login'));

  @override
  Future<void> logout() async {
    await _send('POST', '/logout');
  }

  @override
  Future<EnrollResult> enroll(String code) async => EnrollResult.fromJson(
      _asMap(await _send('POST', '/enroll', {'code': code}), '/enroll'));

  @override
  Future<Posture> posture() async =>
      Posture.fromJson(_asMap(await _send('GET', '/posture'), '/posture'));

  @override
  Future<List<PamEntry>> pamList() async {
    final raw = await _send('GET', '/pam/entries');
    if (raw is! List) {
      throw const EngineException(0, 'unexpected response shape from /pam/entries');
    }
    return raw
        .whereType<Map<String, dynamic>>()
        .map(PamEntry.fromJson)
        .toList(growable: false);
  }

  @override
  Future<PamConnectResult> pamConnect(String entryId) async =>
      PamConnectResult.fromJson(_asMap(
          await _send('POST', '/pam/connect', {'entry_id': entryId}),
          '/pam/connect'));

  @override
  Future<void> pamRequest(String entryId, String reason) async {
    await _send('POST', '/pam/request', {'entry_id': entryId, 'reason': reason});
  }

  @override
  Future<String> zitiDial(String service) async {
    final raw = await _send('POST', '/ziti/dial', {'service': service});
    final map = _asMap(raw, '/ziti/dial');
    final addr = map['addr'] ?? map['url'] ?? map['local_addr'];
    return addr is String ? addr : '';
  }

  @override
  Future<void> zitiClose(String service) async {
    await _send('POST', '/ziti/close', {'service': service});
  }

  @override
  void close() {
    _http?.close(force: true);
    _http = null;
  }
}
