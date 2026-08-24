import 'dart:io' show Platform;

import 'desktop_engine_client.dart';
import 'engine_client.dart';
import 'mobile_engine_client.dart';

/// Picks the right [EngineClient] transport for the current platform:
///
///  * **desktop** (macOS / Linux / Windows) → [DesktopEngineClient], which
///    speaks HTTP to the local `openidx-agent serve` control socket (Phase 1).
///  * **mobile** (iOS / Android) → [MobileEngineClient], which drives the
///    in-process Go engine via the `openidx_engine` gomobile plugin (Phase 2b).
///
/// The [EngineClient] contract and `models.dart` are shared, so the rest of the
/// app (providers, screens) is transport-agnostic.
class EngineClientFactory {
  const EngineClientFactory();

  /// Whether the current platform is a mobile OS.
  static bool get isMobile => Platform.isIOS || Platform.isAndroid;

  /// Whether the current platform is a desktop OS.
  static bool get isDesktop =>
      Platform.isMacOS || Platform.isLinux || Platform.isWindows;

  EngineClient create() {
    if (isMobile) {
      return MobileEngineClient();
    }
    // Desktop (and any non-mobile fallback) uses the control-socket transport.
    return DesktopEngineClient();
  }
}
