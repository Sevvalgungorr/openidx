import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:window_manager/window_manager.dart';

import 'engine/engine_client_factory.dart';
import 'engine/engine_supervisor.dart';
import 'state/providers.dart';
import 'ui/app.dart';
import 'ui/tray.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // The two shells diverge from the very first frame, so split before touching
  // any platform plugin: `window_manager` and `tray_manager` are desktop-only
  // and their method channels have no iOS/Android implementation. Calling them
  // on mobile throws MissingPluginException *before* runApp(), which leaves the
  // app on a blank white screen with no crash dialog.
  if (EngineClientFactory.isMobile) {
    runMobile();
    return;
  }
  await runDesktop();
}

/// Mobile (iOS / Android) boot: no window chrome, no tray, and no sidecar
/// process to supervise — the Go engine is linked in-process via the
/// `openidx_engine` gomobile plugin.
///
/// [engineSupervisorProvider] is deliberately left un-overridden: that is the
/// signal `engineClientProvider` uses to build the transport for the current
/// platform through [EngineClientFactory] (→ `MobileEngineClient`), which
/// starts the engine lazily against the app-support sandbox on first call.
void runMobile() {
  runApp(const ProviderScope(child: OpenIdxApp()));
}

/// Desktop (Windows / macOS / Linux) boot: window chrome, tray icon, and a
/// supervised `openidx-agent serve` sidecar the UI talks to over the control
/// socket.
Future<void> runDesktop() async {
  // --- Desktop window chrome ------------------------------------------------
  await windowManager.ensureInitialized();
  const windowOptions = WindowOptions(
    size: Size(520, 720),
    minimumSize: Size(420, 560),
    center: true,
    title: 'OpenIDX',
  );
  unawaitedShow(windowOptions);

  // --- Start / attach the local engine -------------------------------------
  final supervisor = EngineSupervisor();
  try {
    await supervisor.start();
  } on Object catch (e) {
    // Surface the failure in the UI rather than crashing at boot; the router's
    // error state polls again and offers a retry.
    stderr.writeln('warning: engine not ready at boot: $e');
  }

  // --- System tray ----------------------------------------------------------
  // `late` so the onQuit closure can capture `tray` before the initializer
  // completes (it disposes the controller on Quit).
  late final TrayController tray;
  tray = TrayController(
    onQuit: () async {
      await supervisor.dispose();
      await tray.dispose();
      exit(0);
    },
  );
  await tray.init();

  runApp(
    ProviderScope(
      overrides: [
        engineSupervisorProvider.overrideWithValue(supervisor),
      ],
      child: const OpenIdxApp(),
    ),
  );
}

/// Show the window once it is ready to paint (avoids a white flash).
void unawaitedShow(WindowOptions options) {
  windowManager.waitUntilReadyToShow(options, () async {
    await windowManager.show();
    await windowManager.focus();
  });
}
