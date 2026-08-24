import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/engine/engine_client.dart';
import 'package:openidx_client/engine/mobile_engine_client.dart';
import 'package:openidx_engine/openidx_engine.dart';

/// Verifies that [MobileEngineClient] drives the `openidx_engine` MethodChannel,
/// parses the gomobile JSON strings through the shared `models.dart` factories,
/// and surfaces channel errors as [EngineException].
///
/// > Written, not built here: no Flutter SDK in this checkout. Runs in CI via
/// > `.github/workflows/client-mobile-build.yml` (`flutter test`).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const engineChannel = MethodChannel('openidx_engine');
  const pathProviderChannel =
      MethodChannel('plugins.flutter.io/path_provider');

  final calls = <MethodCall>[];

  /// Install a fake handler for the engine channel that returns [responses]
  /// keyed by method name (a String, or a Function throwing to simulate a Go
  /// error).
  void mockEngine(Map<String, Object? Function()> responses) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(engineChannel, (call) async {
      calls.add(call);
      final handler = responses[call.method];
      if (handler == null) return null;
      return handler();
    });
  }

  setUp(() {
    calls.clear();
    // path_provider: MobileEngineClient resolves the app-support dir on start.
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(pathProviderChannel, (call) async {
      if (call.method == 'getApplicationSupportDirectory') {
        return '/tmp/openidx-test-support';
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(engineChannel, null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(pathProviderChannel, null);
  });

  MobileEngineClient newClient() =>
      MobileEngineClient(engine: OpenidxEngine(channel: engineChannel));

  test('status() parses the engine JSON', () async {
    mockEngine({
      'start': () => null,
      'status': () => '''
        {
          "enrolled": true,
          "agent_id": "agent-123",
          "device_id": "device-abc",
          "server_url": "https://openidx.example.com",
          "ziti_enrolled": true,
          "logged_in": true,
          "user_sub": "user-1",
          "user_email": "alice@example.com",
          "token_expiry": 1893456000,
          "token_expired": false
        }
      ''',
    });

    final status = await newClient().status();

    expect(status.enrolled, isTrue);
    expect(status.agentId, 'agent-123');
    expect(status.serverUrl, 'https://openidx.example.com');
    expect(status.loggedIn, isTrue);
    expect(status.userEmail, 'alice@example.com');
    // start(configDir) must have been invoked once before status.
    expect(calls.map((c) => c.method), contains('start'));
    expect(
      calls.firstWhere((c) => c.method == 'start').arguments,
      containsPair('configDir', '/tmp/openidx-test-support'),
    );
  });

  test('start() is only called once across multiple calls', () async {
    mockEngine({
      'start': () => null,
      'status': () => '{"enrolled": false}',
    });
    final client = newClient();
    await client.status();
    await client.status();
    expect(calls.where((c) => c.method == 'start').length, 1);
  });

  test('pamList() parses a JSON array', () async {
    mockEngine({
      'start': () => null,
      'pamList': () => '''
        [
          {"id":"e1","name":"Prod DB","entry_type":"ssh","require_approval":true,
           "record_session":true,"reach_mode":"ziti","hostname":"db.internal","port":22},
          {"id":"e2","name":"Jump","entry_type":"rdp","require_approval":false,
           "record_session":false,"reach_mode":"direct","hostname":"jump","port":3389}
        ]
      ''',
    });

    final entries = await newClient().pamList();

    expect(entries, hasLength(2));
    expect(entries[0].id, 'e1');
    expect(entries[0].requireApproval, isTrue);
    expect(entries[1].port, 3389);
    expect(entries[1].reachMode, 'direct');
  });

  test('zitiDial() extracts the bound address', () async {
    mockEngine({
      'start': () => null,
      'zitiDial': () => '{"addr":"127.0.0.1:54321"}',
    });
    final addr = await newClient().zitiDial('my-service');
    expect(addr, '127.0.0.1:54321');
  });

  test('channel errors surface as EngineException', () async {
    mockEngine({
      'start': () => null,
      'status': () => throw PlatformException(
            code: 'engine_error',
            message: 'engine not started',
          ),
    });

    expect(
      () => newClient().status(),
      throwsA(isA<EngineException>()
          .having((e) => e.message, 'message', contains('engine not started'))),
    );
  });

  test('malformed JSON surfaces as EngineException', () async {
    mockEngine({
      'start': () => null,
      'status': () => 'not json',
    });
    expect(() => newClient().status(), throwsA(isA<EngineException>()));
  });
}
