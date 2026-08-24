import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/engine/desktop_engine_client.dart';
import 'package:openidx_client/engine/engine_client.dart';

/// Canned JSON matching the ENGINE CONTROL CONTRACT shapes.
const _statusJson = {
  'enrolled': true,
  'agent_id': 'agent-123',
  'device_id': 'device-abc',
  'server_url': 'https://openidx.example.com',
  'ziti_enrolled': true,
  'logged_in': true,
  'user_sub': 'user-sub-1',
  'user_email': 'alice@example.com',
  'token_expiry': 1893456000,
  'token_expired': false,
};

const _pamEntriesJson = [
  {
    'id': 'e1',
    'name': 'Prod DB',
    'entry_type': 'ssh',
    'require_approval': true,
    'record_session': true,
    'reach_mode': 'ziti',
    'hostname': 'db.internal',
    'port': 22,
  },
  {
    'id': 'e2',
    'name': 'Jump Host',
    'entry_type': 'rdp',
    'require_approval': false,
    'record_session': false,
    'reach_mode': 'direct',
    'hostname': 'jump.internal',
    'port': 3389,
  },
];

const _postureJson = {
  'compliant': false,
  'passed': 3,
  'failed': 1,
  'warned': 2,
  'errored': 0,
  'ran_at': '2026-08-24T10:00:00Z',
  'checks': [
    {
      'type': 'disk_encryption',
      'severity': 'high',
      'status': 'pass',
      'score': 1.0,
      'message': 'FileVault enabled',
    },
    {
      'type': 'firewall',
      'severity': 'medium',
      'status': 'fail',
      'score': 0.0,
      'message': 'Firewall disabled',
    },
  ],
};

/// Spins up a loopback HTTP server that answers the control routes with canned
/// JSON. Loopback TCP (rather than a UDS) keeps the test portable across CI
/// runners; the [DesktopEngineClient] speaks identical HTTP/1.1 either way.
Future<HttpServer> _startFakeEngine() async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((HttpRequest req) async {
    Object? body;
    switch (req.uri.path) {
      case '/status':
        body = _statusJson;
        break;
      case '/pam/entries':
        body = _pamEntriesJson;
        break;
      case '/posture':
        body = _postureJson;
        break;
      case '/pam/connect':
        body = {
          'launch_type': 'rdp',
          'connect_url': 'openidx://connect/e2',
          'url': 'https://openidx.example.com/launch/e2',
        };
        break;
      default:
        req.response.statusCode = HttpStatus.notFound;
        await req.response.close();
        return;
    }
    req.response
      ..statusCode = HttpStatus.ok
      ..headers.contentType = ContentType.json
      ..write(jsonEncode(body));
    await req.response.close();
  });
  return server;
}

DesktopEngineClient _clientFor(HttpServer server) {
  return DesktopEngineClient.forEndpoint(
    EngineEndpoint.tcp(
      host: server.address.address,
      port: server.port,
      token: 'test-token',
    ),
  );
}

void main() {
  late HttpServer server;
  late DesktopEngineClient client;

  setUp(() async {
    server = await _startFakeEngine();
    client = _clientFor(server);
  });

  tearDown(() async {
    client.close();
    await server.close(force: true);
  });

  test('status() parses the AgentStatus contract', () async {
    final status = await client.status();
    expect(status.enrolled, isTrue);
    expect(status.agentId, 'agent-123');
    expect(status.deviceId, 'device-abc');
    expect(status.serverUrl, 'https://openidx.example.com');
    expect(status.zitiEnrolled, isTrue);
    expect(status.loggedIn, isTrue);
    expect(status.userSub, 'user-sub-1');
    expect(status.userEmail, 'alice@example.com');
    expect(status.tokenExpiry, 1893456000);
    expect(status.tokenExpired, isFalse);
  });

  test('pamList() parses the PamEntry list contract', () async {
    final entries = await client.pamList();
    expect(entries, hasLength(2));

    final first = entries.first;
    expect(first.id, 'e1');
    expect(first.name, 'Prod DB');
    expect(first.entryType, 'ssh');
    expect(first.requireApproval, isTrue);
    expect(first.recordSession, isTrue);
    expect(first.reachMode, 'ziti');
    expect(first.hostname, 'db.internal');
    expect(first.port, 22);

    expect(entries[1].requireApproval, isFalse);
    expect(entries[1].port, 3389);
  });

  test('posture() parses Posture + nested checks', () async {
    final posture = await client.posture();
    expect(posture.compliant, isFalse);
    expect(posture.passed, 3);
    expect(posture.failed, 1);
    expect(posture.warned, 2);
    expect(posture.errored, 0);
    expect(posture.ranAt, '2026-08-24T10:00:00Z');
    expect(posture.checks, hasLength(2));
    expect(posture.checks.first.type, 'disk_encryption');
    expect(posture.checks.first.score, 1.0);
    expect(posture.checks[1].status, 'fail');
  });

  test('pamConnect() parses launch fields and prefers connect_url', () async {
    final result = await client.pamConnect('e2');
    expect(result.launchType, 'rdp');
    expect(result.connectUrl, 'openidx://connect/e2');
    expect(result.url, 'https://openidx.example.com/launch/e2');
    expect(result.launchTarget, 'openidx://connect/e2');
  });

  test('non-2xx responses throw a typed EngineException', () async {
    // /login is not handled by the fake → 404.
    expect(
      () => client.login(),
      throwsA(isA<EngineException>()
          .having((e) => e.status, 'status', HttpStatus.notFound)),
    );
  });
}
