import 'package:flutter_test/flutter_test.dart';
import 'package:openidx_client/features/totp.dart';

/// RFC 6238 Appendix B test vectors. The shared secret is the ASCII string
/// "12345678901234567890" (20 bytes) → base32 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`.
/// The published codes are 8 digits, SHA-1, 30s period.
///
/// > Written, not built here; verified in CI via `flutter test`.
void main() {
  // ASCII "12345678901234567890" in base32.
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  String codeAt(int unixSeconds) => Totp.now(
        secret,
        digits: 8,
        periodSeconds: 30,
        algorithm: TotpAlgorithm.sha1,
        atMillis: unixSeconds * 1000,
      );

  group('RFC 6238 SHA-1 8-digit vectors', () {
    test('T = 59', () => expect(codeAt(59), '94287082'));
    test('T = 1111111109', () => expect(codeAt(1111111109), '07081804'));
    test('T = 1111111111', () => expect(codeAt(1111111111), '14050471'));
    test('T = 1234567890', () => expect(codeAt(1234567890), '89005924'));
    test('T = 2000000000', () => expect(codeAt(2000000000), '69279037'));
  });

  test('6-digit default is the 8-digit code truncated to 6 low digits', () {
    // The standard authenticator UI uses 6 digits.
    final six = Totp.now(secret, atMillis: 59 * 1000);
    expect(six, '287082');
    expect(six.length, 6);
  });

  test('base32 decode tolerates spaces and lowercase', () {
    final a = Totp.base32Decode('gezd gnbv gy3t qojq');
    final b = Totp.base32Decode('GEZDGNBVGY3TQOJQ');
    expect(a, equals(b));
  });

  test('secondsRemaining counts down within the period', () {
    // 5 seconds into a 30s window → 25 remaining.
    expect(Totp.secondsRemaining(periodSeconds: 30, atMillis: 5 * 1000), 25);
    // Exactly on a boundary → full window.
    expect(Totp.secondsRemaining(periodSeconds: 30, atMillis: 30 * 1000), 30);
  });

  group('otpauth URI parsing', () {
    test('parses issuer/account/secret and defaults', () {
      final acct = OtpAccount.parseUri(
        'otpauth://totp/OpenIDX:alice@example.com?secret=$secret&issuer=OpenIDX',
      );
      expect(acct.issuer, 'OpenIDX');
      expect(acct.account, 'alice@example.com');
      expect(acct.secret, secret);
      expect(acct.digits, 6);
      expect(acct.period, 30);
      expect(acct.algorithm, TotpAlgorithm.sha1);
    });

    test('rejects non-otpauth URIs', () {
      expect(() => OtpAccount.parseUri('https://example.com'),
          throwsA(isA<FormatException>()));
    });

    test('round-trips through JSON', () {
      final acct = OtpAccount.parseUri(
        'otpauth://totp/Acme:bob?secret=$secret&algorithm=SHA256&digits=8&period=60',
      );
      final restored = OtpAccount.fromJson(acct.toJson());
      expect(restored.issuer, 'Acme');
      expect(restored.account, 'bob');
      expect(restored.digits, 8);
      expect(restored.period, 60);
      expect(restored.algorithm, TotpAlgorithm.sha256);
    });
  });
}
