import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../state/providers.dart';

/// Settings: shows the connected server, signs out, or quits the app.
class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  Future<void> _signOut(BuildContext context, WidgetRef ref) async {
    try {
      await ref.read(engineActionsProvider).logout();
      if (context.mounted) Navigator.of(context).pop();
    } on Object catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Sign out failed: $e')));
      }
    }
  }

  Future<void> _quit(BuildContext context, WidgetRef ref) async {
    // Let the supervisor tear down a spawned engine before we exit.
    await ref.read(engineSupervisorProvider).dispose();
    exit(0);
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final status = ref.watch(currentStatusProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          ListTile(
            leading: const Icon(Icons.cloud_outlined),
            title: const Text('Server'),
            subtitle: Text(status.serverUrl.isEmpty ? '—' : status.serverUrl),
          ),
          ListTile(
            leading: const Icon(Icons.badge_outlined),
            title: const Text('Signed in as'),
            subtitle: Text(
              status.userEmail.isNotEmpty ? status.userEmail : status.userSub,
            ),
          ),
          ListTile(
            leading: const Icon(Icons.devices_other_outlined),
            title: const Text('Device ID'),
            subtitle: Text(status.deviceId.isEmpty ? '—' : status.deviceId),
          ),
          const Divider(),
          ListTile(
            leading: const Icon(Icons.logout),
            title: const Text('Sign out'),
            onTap: () => _signOut(context, ref),
          ),
          ListTile(
            leading: const Icon(Icons.power_settings_new),
            title: const Text('Quit OpenIDX'),
            onTap: () => _quit(context, ref),
          ),
        ],
      ),
    );
  }
}
