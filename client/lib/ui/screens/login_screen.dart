import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../state/providers.dart';

/// Shown when the device is enrolled but no user is signed in.
/// The button hands off to the engine's `/login` (browser-based OIDC flow).
class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});

  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> {
  bool _busy = false;
  String? _error;

  Future<void> _signIn() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final actions = ref.read(engineActionsProvider);
      if (Platform.isAndroid || Platform.isIOS) {
        // Mobile: the engine can't open a browser itself. Get the authorize URL
        // (this also persists the PKCE flow to disk so it survives a process
        // kill) and open it in the system browser — OAuth + MFA happen there.
        // The server redirects to openidx://oauth-callback, which the OS routes
        // back to the app. Completion is owned by the app-level
        // MobileOAuthLoginHandler (see mobile/oauth_login_handler.dart), NOT this
        // screen: Android frequently kills the app during the browser step and
        // cold-starts it to deliver the redirect, so an in-screen
        // `await callbacks.first` would never resolve. The router advances to
        // home once the handler completes login and refreshes status. The button
        // simply stops spinning once the browser is open.
        final url = await actions.loginStart();
        await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
      } else {
        await actions.login();
      }
      // Router reacts to the refreshed status; no manual navigation needed.
    } on Object catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final status = ref.watch(currentStatusProvider);

    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.shield_outlined, size: 56),
                const SizedBox(height: 16),
                Text(
                  'OpenIDX',
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 4),
                if (status.serverUrl.isNotEmpty)
                  Text(
                    status.serverUrl,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                const SizedBox(height: 28),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton.icon(
                    onPressed: _busy ? null : _signIn,
                    icon: _busy
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.login),
                    label: const Text('Sign in with OpenIDX'),
                  ),
                ),
                if (_error != null) ...[
                  const SizedBox(height: 16),
                  Text(
                    _error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                      fontSize: 13,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
