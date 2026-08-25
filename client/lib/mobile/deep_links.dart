import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

// Deep-link platform config:
//   Android — client/android/app/src/main/AndroidManifest.xml is committed with
//     a <queries> block (so url_launcher can open a browser on Android 11+) and
//     an openidx://oauth-callback intent-filter (so the OAuth redirect returns
//     to the app). `flutter create` won't overwrite it.
//   iOS — TODO: iOS needs a CFBundleURLTypes entry registering the `openidx`
//     URL scheme in ios/Runner/Info.plist for the deep-link redirect to reach
//     the app, e.g.:
//         <key>CFBundleURLTypes</key>
//         <array>
//           <dict>
//             <key>CFBundleURLName</key><string>com.example.openidx_client</string>
//             <key>CFBundleURLSchemes</key><array><string>openidx</string></array>
//           </dict>
//         </array>
//     Info.plist is not committed here (flutter generates most of it); add this
//     when wiring iOS. Android is the platform under test.

/// A parsed inbound deep link the app knows how to route.
sealed class OpenidxDeepLink {
  const OpenidxDeepLink();

  /// Parse a `openidx://…` URI, or null if it isn't one we handle.
  static OpenidxDeepLink? parse(Uri uri) {
    if (uri.scheme != 'openidx') return null;
    switch (uri.host) {
      case 'oauth-callback':
        final code = uri.queryParameters['code'];
        if (code == null || code.isEmpty) return null;
        return OAuthCallbackLink(code: code, raw: uri);
      case 'approve':
        // openidx://approve/<challengeId>
        final id = uri.pathSegments.isNotEmpty ? uri.pathSegments.first : '';
        if (id.isEmpty) return null;
        return ApproveLink(challengeId: id);
      default:
        return null;
    }
  }
}

/// `openidx://oauth-callback?code=…` — the browser PKCE fallback redirect.
class OAuthCallbackLink extends OpenidxDeepLink {
  const OAuthCallbackLink({required this.code, required this.raw});
  final String code;
  final Uri raw;
}

/// `openidx://approve/<challengeId>` — a push-approval deep link.
class ApproveLink extends OpenidxDeepLink {
  const ApproveLink({required this.challengeId});
  final String challengeId;
}

/// Listens for inbound deep links (cold-start + while running) via `app_links`
/// and exposes them as a stream. The router/UI subscribes and navigates;
/// `AuthService.browserAuthorize` awaits the next [OAuthCallbackLink].
class DeepLinkService {
  DeepLinkService({AppLinks? appLinks}) : _appLinks = appLinks ?? AppLinks();

  final AppLinks _appLinks;
  final _controller = StreamController<OpenidxDeepLink>.broadcast();

  /// Full `openidx://oauth-callback?code=…&state=…` URIs, broadcast so the login
  /// flow can await the redirect that comes back from the system browser. Kept
  /// separate from [links] because the login screen needs the *raw* Uri (code +
  /// state) to hand to the engine's `loginFinish`, not the parsed link.
  final _oauthController = StreamController<Uri>.broadcast();
  StreamSubscription<Uri>? _sub;
  bool _initialized = false;

  /// The most recent `openidx://oauth-callback` URI seen, retained so a late
  /// subscriber (e.g. the app-level login handler that starts up *after* the OS
  /// delivered the cold-start deep link) can still complete login. Cleared once
  /// login succeeds is the caller's responsibility; re-subscribers replay it via
  /// [oauthCallbackUris].
  Uri? _lastOAuthCallback;

  Stream<OpenidxDeepLink> get links => _controller.stream;

  /// Full callback URIs for the browser deep-link OAuth flow. This stream
  /// **replays** the last-seen oauth-callback to every new subscriber before the
  /// live events, so a handler that subscribes late (cold start) still receives
  /// the redirect that arrived while the app was launching.
  Stream<Uri> get oauthCallbackUris async* {
    final replay = _lastOAuthCallback;
    if (replay != null) yield replay;
    yield* _oauthController.stream;
  }

  /// The initial (cold-start) `openidx://oauth-callback` URI, if the app was
  /// launched by the OAuth redirect and no callback has yet been consumed. The
  /// app-level handler checks this on startup so a cold start completes login
  /// even if it subscribed to [oauthCallbackUris] after the event fired.
  Future<Uri?> initialOAuthCallback() async {
    await init();
    return _lastOAuthCallback;
  }

  /// Begin listening. Emits the initial (cold-start) link, if any, then all
  /// subsequent ones.
  Future<void> init() async {
    if (_initialized) return;
    _initialized = true;

    final initial = await _appLinks.getInitialLink();
    if (initial != null) _emit(initial);

    _sub = _appLinks.uriLinkStream.listen(_emit);
  }

  /// Convenience for the browser OAuth fallback: resolve with the next
  /// `code` from an [OAuthCallbackLink].
  Future<String> nextOAuthCode() {
    return links
        .where((l) => l is OAuthCallbackLink)
        .cast<OAuthCallbackLink>()
        .map((l) => l.code)
        .first;
  }

  void _emit(Uri uri) {
    final link = OpenidxDeepLink.parse(uri);
    if (link == null) return;
    _controller.add(link);
    // Also push the FULL callback Uri onto the oauth stream so the login flow
    // can complete the code+state exchange with the engine, and retain it so a
    // late subscriber (cold start) can still replay it.
    if (link is OAuthCallbackLink) {
      _lastOAuthCallback = link.raw;
      _oauthController.add(link.raw);
    }
  }

  /// Called by the login handler once a callback has been consumed so it is not
  /// replayed to future subscribers (avoids re-submitting a spent code).
  void clearOAuthCallback() {
    _lastOAuthCallback = null;
  }

  Future<void> dispose() async {
    await _sub?.cancel();
    await _controller.close();
    await _oauthController.close();
  }
}

final deepLinkServiceProvider = Provider<DeepLinkService>((ref) {
  final service = DeepLinkService();
  ref.onDispose(service.dispose);
  return service;
});

/// Broadcast of full `openidx://oauth-callback` URIs. Reading this provider
/// ensures the [DeepLinkService] is listening (idempotent [init]) and exposes
/// its [DeepLinkService.oauthCallbackUris] stream. The login screen awaits the
/// next event to finish the browser deep-link OAuth flow.
final oauthCallbackUriProvider = Provider<Stream<Uri>>((ref) {
  final service = ref.watch(deepLinkServiceProvider);
  // Fire-and-forget: init is idempotent and returns immediately if already
  // listening; the stream replays the last oauth-callback so a late subscriber
  // (cold start) still receives the redirect that arrived while launching.
  unawaited(service.init());
  return service.oauthCallbackUris;
});
