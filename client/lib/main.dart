import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:window_manager/window_manager.dart';

import 'engine/engine_supervisor.dart';
import 'state/providers.dart';
import 'ui/app.dart';
import 'ui/tray.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

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
