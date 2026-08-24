import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Self-contained RFC 6238 TOTP + RFC 4648 base32 implementation.
///
/// We roll our own (over pulling an `otp` package) so the exact algorithm is
/// pinned and unit-testable against the RFC 6238 vectors — see
/// `test/totp_test.dart`. Only SHA-1 / 6-digit / 30s is exercised by the
/// authenticator UI, but the parameters are configurable for otpauth URIs that
/// specify SHA-256/512 or a different digit count.
class Totp {
  const Totp._();

  /// Generate the current TOTP code for [secretBase32] at [atMillis]
  /// (defaults to now).
  static String now(
    String secretBase32, {
    int digits = 6,
    int periodSeconds = 30,
    TotpAlgorithm algorithm = TotpAlgorithm.sha1,
    int? atMillis,
  }) {
    final ms = atMillis ?? DateTime.now().millisecondsSinceEpoch;
    final counter = ms ~/ 1000 ~/ periodSeconds;
    return generate(
      secretBase32,
      counter: counter,
      digits: digits,
      algorithm: algorithm,
    );
  }

  /// Seconds remaining in the current [periodSeconds] window (for the UI ring).
  static int secondsRemaining({int periodSeconds = 30, int? atMillis}) {
    final ms = atMillis ?? DateTime.now().millisecondsSinceEpoch;
    final seconds = ms ~/ 1000;
    return periodSeconds - (seconds % periodSeconds);
  }

  /// HOTP/TOTP core: HMAC(secret, counter) → dynamic-truncation → N digits.
  static String generate(
    String secretBase32, {
    required int counter,
    int digits = 6,
    TotpAlgorithm algorithm = TotpAlgorithm.sha1,
  }) {
    final key = base32Decode(secretBase32);
    final msg = _counterBytes(counter);
    final mac = Hmac(algorithm.digest, key).convert(msg).bytes;

    // RFC 4226 dynamic truncation.
    final offset = mac[mac.length - 1] & 0x0f;
    final binary = ((mac[offset] & 0x7f) << 24) |
        ((mac[offset + 1] & 0xff) << 16) |
        ((mac[offset + 2] & 0xff) << 8) |
        (mac[offset + 3] & 0xff);

    final otp = binary % _pow10(digits);
    return otp.toString().padLeft(digits, '0');
  }

  static Uint8List _counterBytes(int counter) {
    final bytes = Uint8List(8);
    var value = counter;
    for (var i = 7; i >= 0; i--) {
      bytes[i] = value & 0xff;
      value >>= 8;
    }
    return bytes;
  }

  static int _pow10(int n) {
    var result = 1;
    for (var i = 0; i < n; i++) {
      result *= 10;
    }
    return result;
  }

  /// RFC 4648 base32 decode (no padding required; case-insensitive; spaces
  /// ignored — authenticator secrets are often grouped with spaces).
  static Uint8List base32Decode(String input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    final clean =
        input.toUpperCase().replaceAll(RegExp(r'[\s=]'), '');
    var bits = 0;
    var value = 0;
    final out = <int>[];
    for (final ch in clean.codeUnits) {
      final idx = alphabet.indexOf(String.fromCharCode(ch));
      if (idx < 0) {
        throw FormatException('invalid base32 character: ${String.fromCharCode(ch)}');
      }
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.add((value >> bits) & 0xff);
      }
    }
    return Uint8List.fromList(out);
  }
}

enum TotpAlgorithm {
  sha1(sha1_),
  sha256(sha256_),
  sha512(sha512_);

  const TotpAlgorithm(this._digestGetter);
  final Hash Function() _digestGetter;
  Hash get digest => _digestGetter();

  static TotpAlgorithm parse(String? name) {
    switch (name?.toUpperCase()) {
      case 'SHA256':
      case 'SHA-256':
        return TotpAlgorithm.sha256;
      case 'SHA512':
      case 'SHA-512':
        return TotpAlgorithm.sha512;
      default:
        return TotpAlgorithm.sha1;
    }
  }
}

// Indirection so the enum can reference `crypto`'s Hash singletons.
Hash sha1_() => sha1;
Hash sha256_() => sha256;
Hash sha512_() => sha512;

/// A saved authenticator account, parsed from an `otpauth://` URI.
class OtpAccount {
  const OtpAccount({
    required this.issuer,
    required this.account,
    required this.secret,
    required this.digits,
    required this.period,
    required this.algorithm,
  });

  final String issuer;
  final String account;
  final String secret;
  final int digits;
  final int period;
  final TotpAlgorithm algorithm;

  /// Stable id for secure-storage keying.
  String get id => '$issuer:$account';

  String code({int? atMillis}) => Totp.now(
        secret,
        digits: digits,
        periodSeconds: period,
        algorithm: algorithm,
        atMillis: atMillis,
      );

  /// Parse an `otpauth://totp/Issuer:account?secret=…&issuer=…&digits=…` URI.
  static OtpAccount parseUri(String uri) {
    final parsed = Uri.parse(uri.trim());
    if (parsed.scheme != 'otpauth' || parsed.host.toLowerCase() != 'totp') {
      throw const FormatException('not an otpauth://totp URI');
    }
    final secret = parsed.queryParameters['secret'];
    if (secret == null || secret.isEmpty) {
      throw const FormatException('otpauth URI missing secret');
    }
    // Label is "Issuer:account" (issuer optional), possibly URL-encoded.
    final label = Uri.decodeComponent(
        parsed.pathSegments.isNotEmpty ? parsed.pathSegments.last : '');
    var issuer = parsed.queryParameters['issuer'] ?? '';
    var account = label;
    final sep = label.indexOf(':');
    if (sep >= 0) {
      if (issuer.isEmpty) issuer = label.substring(0, sep).trim();
      account = label.substring(sep + 1).trim();
    }
    return OtpAccount(
      issuer: issuer,
      account: account,
      secret: secret,
      digits: int.tryParse(parsed.queryParameters['digits'] ?? '') ?? 6,
      period: int.tryParse(parsed.queryParameters['period'] ?? '') ?? 30,
      algorithm: TotpAlgorithm.parse(parsed.queryParameters['algorithm']),
    );
  }

  Map<String, dynamic> toJson() => {
        'issuer': issuer,
        'account': account,
        'secret': secret,
        'digits': digits,
        'period': period,
        'algorithm': algorithm.name,
      };

  factory OtpAccount.fromJson(Map<String, dynamic> j) => OtpAccount(
        issuer: (j['issuer'] ?? '') as String,
        account: (j['account'] ?? '') as String,
        secret: (j['secret'] ?? '') as String,
        digits: (j['digits'] ?? 6) as int,
        period: (j['period'] ?? 30) as int,
        algorithm: TotpAlgorithm.parse(j['algorithm'] as String?),
      );

  static String encodeList(List<OtpAccount> accounts) =>
      jsonEncode(accounts.map((a) => a.toJson()).toList());

  static List<OtpAccount> decodeList(String json) {
    final raw = jsonDecode(json);
    if (raw is! List) return const [];
    return raw
        .whereType<Map<String, dynamic>>()
        .map(OtpAccount.fromJson)
        .toList();
  }
}
