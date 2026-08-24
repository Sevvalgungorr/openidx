import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../engine/models.dart';
import '../../state/providers.dart';
import 'pam_screen.dart';
import 'settings_screen.dart';

/// Landing screen once enrolled + signed in: status card, posture summary,
/// and navigation to PAM / Settings.
class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final status = ref.watch(currentStatusProvider);
    final postureAsync = ref.watch(postureProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('OpenIDX'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh),
            onPressed: () {
              ref.invalidate(statusProvider);
              ref.invalidate(postureProvider);
            },
          ),
          IconButton(
            tooltip: 'Settings',
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute<void>(
                builder: (_) => const SettingsScreen(),
              ),
            ),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _StatusCard(status: status),
          const SizedBox(height: 16),
          _PostureCard(postureAsync: postureAsync),
          const SizedBox(height: 16),
          Card(
            child: ListTile(
              leading: const Icon(Icons.dns_outlined),
              title: const Text('Privileged Access'),
              subtitle: const Text('Connect to servers and secrets'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute<void>(builder: (_) => const PamScreen()),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.status});

  final AgentStatus status;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.verified_user_outlined),
                const SizedBox(width: 8),
                Text(
                  'Device status',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
              ],
            ),
            const Divider(height: 24),
            _kv(context, 'User', status.userEmail.isNotEmpty
                ? status.userEmail
                : status.userSub),
            _kv(context, 'Server', status.serverUrl),
            _kv(context, 'Enrolled', status.enrolled ? 'Yes' : 'No'),
            _kv(context, 'Ziti', status.zitiEnrolled ? 'Connected' : 'Off'),
            if (status.tokenExpired)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(
                  'Session expired — sign in again.',
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _kv(BuildContext context, String k, String v) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 84,
            child: Text(k, style: Theme.of(context).textTheme.bodySmall),
          ),
          Expanded(
            child: Text(v.isEmpty ? '—' : v),
          ),
        ],
      ),
    );
  }
}

class _PostureCard extends StatelessWidget {
  const _PostureCard({required this.postureAsync});

  final AsyncValue<Posture> postureAsync;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: postureAsync.when(
          loading: () => const SizedBox(
            height: 48,
            child: Center(child: CircularProgressIndicator()),
          ),
          error: (e, _) => Text('Posture unavailable: $e'),
          data: (posture) {
            final color = posture.compliant
                ? Colors.green
                : Theme.of(context).colorScheme.error;
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(
                      posture.compliant
                          ? Icons.check_circle_outline
                          : Icons.error_outline,
                      color: color,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      posture.compliant ? 'Compliant' : 'Not compliant',
                      style: Theme.of(context)
                          .textTheme
                          .titleMedium
                          ?.copyWith(color: color),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 12,
                  runSpacing: 8,
                  children: [
                    _chip(context, 'Passed', posture.passed, Colors.green),
                    _chip(context, 'Failed', posture.failed,
                        Theme.of(context).colorScheme.error),
                    _chip(context, 'Warned', posture.warned, Colors.orange),
                    _chip(context, 'Errored', posture.errored, Colors.grey),
                  ],
                ),
                if (posture.checks.isNotEmpty) ...[
                  const Divider(height: 24),
                  ...posture.checks.map(
                    (c) => ListTile(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      leading: Icon(_iconFor(c.status), size: 20),
                      title: Text(c.type),
                      subtitle: c.message.isEmpty ? null : Text(c.message),
                      trailing: Text(c.severity),
                    ),
                  ),
                ],
              ],
            );
          },
        ),
      ),
    );
  }

  Widget _chip(BuildContext context, String label, int n, Color color) {
    return Chip(
      label: Text('$label: $n'),
      side: BorderSide(color: color.withValues(alpha: 0.5)),
    );
  }

  IconData _iconFor(String status) {
    switch (status.toLowerCase()) {
      case 'pass':
      case 'passed':
        return Icons.check_circle_outline;
      case 'fail':
      case 'failed':
        return Icons.cancel_outlined;
      case 'warn':
      case 'warned':
        return Icons.warning_amber_outlined;
      default:
        return Icons.help_outline;
    }
  }
}
