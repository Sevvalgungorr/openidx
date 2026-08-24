// Placeholder so `flutter create` (run in CI to materialize the platform
// runners) does not generate its default widget_test.dart, which references a
// `MyApp` this project doesn't define. Real coverage lives in
// engine_client_test.dart, mobile_engine_client_test.dart, and totp_test.dart.
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('placeholder', () {
    expect(true, isTrue);
  });
}
