import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../mobile/oauth_login_handler.dart';
import '../state/providers.dart';
import 'mobile_shell.dart';
import 'screens/enroll_screen.dart';
import 'screens/home_screen.dart';
import 'screens/login_screen.dart';

/// Root widget. Chooses the initial screen from live agent status:
///   not enrolled            → EnrollScreen
///   enrolled, not logged in → LoginScreen
///   enrolled + logged in    → HomeScreen
class OpenIdxApp extends ConsumerWidget {
  const OpenIdxApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // On mobile, an app-level handler owns OAuth-callback login completion so it
    // works even when Android cold-starts the app to deliver the redirect (the
    // login screen that was awaiting the callback is gone by then). Mounting it
    // above the router means it lives for the whole app session, independent of
    // which screen is shown. Desktop uses the loopback flow and is unaffected.
    const router = _RootRouter();
    final home = (Platform.isAndroid || Platform.isIOS)
        ? const MobileOAuthLoginHandler(child: router)
        : router;
    return MaterialApp(
      title: 'OpenIDX',
      debugShowCheckedModeBanner: false,
      theme: _lightTheme,
      darkTheme: _darkTheme,
      themeMode: ThemeMode.system,
      home: home,
    );
  }
}

class _RootRouter extends ConsumerWidget {
  const _RootRouter();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final statusAsync = ref.watch(statusProvider);

    return statusAsync.when(
      loading: () => const _Splash(),
      error: (err, _) => _EngineError(message: err.toString()),
      data: (status) {
        if (!status.enrolled) return const EnrollScreen();
        if (!status.loggedIn) return const LoginScreen();
        // Mobile gets the bottom-nav shell (Codes/Approvals/Access/Settings);
        // desktop keeps its single-pane HomeScreen inside the window/tray shell.
        if (Platform.isIOS || Platform.isAndroid) return const MobileShell();
        return const HomeScreen();
      },
    );
  }
}

class _Splash extends StatelessWidget {
  const _Splash();

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
              width: 36,
              height: 36,
              child: CircularProgressIndicator(),
            ),
            SizedBox(height: 16),
            Text('Connecting to OpenIDX agent…'),
          ],
        ),
      ),
    );
  }
}

class _EngineError extends ConsumerWidget {
  const _EngineError({required this.message});

  final String message;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.cloud_off, size: 48),
              const SizedBox(height: 12),
              const Text(
                'Cannot reach the OpenIDX agent',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 8),
              Text(
                message,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 13),
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: () => ref.invalidate(statusProvider),
                icon: const Icon(Icons.refresh),
                label: const Text('Retry'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

const _seed = Color(0xFF2F6FED);

final ThemeData _lightTheme = ThemeData(
  useMaterial3: true,
  colorScheme: ColorScheme.fromSeed(seedColor: _seed),
);

final ThemeData _darkTheme = ThemeData(
  useMaterial3: true,
  colorScheme: ColorScheme.fromSeed(
    seedColor: _seed,
    brightness: Brightness.dark,
  ),
);
