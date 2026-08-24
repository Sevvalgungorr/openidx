import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../mobile/app_lock.dart';
import 'screens/mobile/approvals_screen.dart';
import 'screens/mobile/authenticator_screen.dart';
import 'screens/mobile/my_access_screen.dart';
import 'screens/settings_screen.dart';

/// Bottom-navigation shell used on iOS/Android (desktop keeps its window/tray
/// shell in `main.dart`). Tabs: Codes / Approvals / Access / Settings.
///
/// The whole shell is wrapped in an [AppLockGate] so biometric app-lock covers
/// every tab. Notifications and push-approval are reached via deep links /
/// the notifications action rather than a dedicated tab, to keep the bar to
/// four primary destinations.
class MobileShell extends ConsumerStatefulWidget {
  const MobileShell({super.key});

  @override
  ConsumerState<MobileShell> createState() => _MobileShellState();
}

class _MobileShellState extends ConsumerState<MobileShell> {
  int _index = 0;

  static const _tabs = <Widget>[
    AuthenticatorScreen(),
    ApprovalsScreen(),
    MyAccessScreen(),
    SettingsScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    return AppLockGate(
      child: Scaffold(
        body: IndexedStack(index: _index, children: _tabs),
        bottomNavigationBar: NavigationBar(
          selectedIndex: _index,
          onDestinationSelected: (i) => setState(() => _index = i),
          destinations: const [
            NavigationDestination(
                icon: Icon(Icons.pin_outlined),
                selectedIcon: Icon(Icons.pin),
                label: 'Codes'),
            NavigationDestination(
                icon: Icon(Icons.approval_outlined),
                selectedIcon: Icon(Icons.approval),
                label: 'Approvals'),
            NavigationDestination(
                icon: Icon(Icons.vpn_key_outlined),
                selectedIcon: Icon(Icons.vpn_key),
                label: 'Access'),
            NavigationDestination(
                icon: Icon(Icons.settings_outlined),
                selectedIcon: Icon(Icons.settings),
                label: 'Settings'),
          ],
        ),
      ),
    );
  }
}
