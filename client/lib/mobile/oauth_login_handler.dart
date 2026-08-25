import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/providers.dart';
import 'deep_links.dart';

/// App-level owner of mobile OAuth login completion.
///
/// The `openidx://oauth-callback` redirect must complete login whether the app
/// is **warm** (it stayed alive during the browser step → onNewIntent → the
/// deep-link stream) or **cold** (Android killed the app while the browser was
/// foreground and relaunched it to deliver the redirect — the login screen that
/// was awaiting the callback is gone, and the in-memory PKCE flow is lost but was
/// persisted to disk by the engine's LoginStart). Because completion can no
/// longer live inside the login screen, this widget wraps the whole app: it
/// subscribes to oauth-callback URIs AND checks the cold-start initial link, and
/// on either path calls `loginFinish` (which reloads the persisted PKCE material
/// on the engine side when needed) then refreshes status so the router advances
/// to home.
class MobileOAuthLoginHandler extends ConsumerStatefulWidget {
  const MobileOAuthLoginHandler({required this.child, super.key});

  final Widget child;

  @override
  ConsumerState<MobileOAuthLoginHandler> createState() =>
      _MobileOAuthLoginHandlerState();
}

class _MobileOAuthLoginHandlerState
    extends ConsumerState<MobileOAuthLoginHandler> {
  StreamSubscription<Uri>? _sub;

  /// Codes already handed to loginFinish, to guard against double-completion
  /// (the replayed initial link + the live stream can surface the same URI).
  final Set<String> _handled = <String>{};

  @override
  void initState() {
    super.initState();
    // Subscribe to the replayed+live callback stream. The stream replays the
    // last-seen callback, so this covers both the warm path and a cold start
    // where the redirect arrived before we subscribed.
    _sub = ref.read(oauthCallbackUriProvider).listen(_complete);
    // Also explicitly check the initial link in case it was delivered before any
    // stream machinery was wired up.
    unawaited(_checkInitial());
  }

  Future<void> _checkInitial() async {
    final service = ref.read(deepLinkServiceProvider);
    final initial = await service.initialOAuthCallback();
    if (initial != null) _complete(initial);
  }

  Future<void> _complete(Uri uri) async {
    final code = uri.queryParameters['code'];
    if (code == null || code.isEmpty) return;
    if (!_handled.add(code)) return; // already completing/completed this code

    try {
      await ref.read(engineActionsProvider).loginFinish(uri.toString());
      // Success: stop replaying this callback to any future subscriber so a
      // spent authorization code is never re-submitted.
      ref.read(deepLinkServiceProvider).clearOAuthCallback();
    } on Object {
      // Quietly ignore: a stale/duplicate callback (e.g. "no login in progress")
      // must not crash the app. The user can retry sign-in; a genuine failure is
      // surfaced by the login screen staying put.
      _handled.remove(code); // allow a genuine retry of the same code
    }
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
