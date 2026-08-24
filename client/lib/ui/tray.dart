import 'dart:io';

import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

/// Wires up the system tray icon + menu and "close-to-tray" behaviour.
///
/// Menu: Open · Sign in/out · Quit. The sign-in/out item is a no-op hook here
/// (the actual auth flow lives in the UI); it simply surfaces + focuses the
/// window so the user can act on it.
class TrayController with TrayListener, WindowListener {
  TrayController({required this.onQuit});

  /// Invoked when the user chooses Quit; should dispose the engine supervisor
  /// and exit the process.
  final Future<void> Function() onQuit;

  bool _signedIn = false;

  Future<void> init() async {
    trayManager.addListener(this);
    windowManager.addListener(this);

    // Intercept the window close button so we can hide-to-tray instead.
    await windowManager.setPreventClose(true);

    await trayManager.setIcon(_iconPath);
    await _rebuildMenu();
  }

  Future<void> dispose() async {
    trayManager.removeListener(this);
    windowManager.removeListener(this);
    await trayManager.destroy();
  }

  /// Reflect auth state in the tray menu label.
  Future<void> setSignedIn(bool value) async {
    if (_signedIn == value) return;
    _signedIn = value;
    await _rebuildMenu();
  }

  String get _iconPath => Platform.isWindows
      ? 'assets/tray/icon.ico'
      : 'assets/tray/icon.png';

  Future<void> _rebuildMenu() async {
    final menu = Menu(
      items: [
        MenuItem(key: 'open', label: 'Open OpenIDX'),
        MenuItem.separator(),
        MenuItem(
          key: 'auth',
          label: _signedIn ? 'Sign out' : 'Sign in',
        ),
        MenuItem.separator(),
        MenuItem(key: 'quit', label: 'Quit'),
      ],
    );
    await trayManager.setContextMenu(menu);
  }

  Future<void> _showWindow() async {
    await windowManager.show();
    await windowManager.focus();
  }

  // --- TrayListener ---------------------------------------------------------

  @override
  void onTrayIconMouseDown() {
    _showWindow();
  }

  @override
  void onTrayIconRightMouseDown() {
    trayManager.popUpContextMenu();
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    switch (menuItem.key) {
      case 'open':
      case 'auth':
        _showWindow();
        break;
      case 'quit':
        onQuit();
        break;
    }
  }

  // --- WindowListener -------------------------------------------------------

  @override
  void onWindowClose() {
    // Close-to-tray: hide instead of terminating.
    windowManager.hide();
  }
}
