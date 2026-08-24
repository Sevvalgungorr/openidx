import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../api/governance.dart';
import '../../../state/mobile_providers.dart';

/// The signed-in user's own access requests and their statuses (my-access).
class MyAccessScreen extends ConsumerWidget {
  const MyAccessScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final requests = ref.watch(myRequestsProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('My Access')),
      body: RefreshIndicator(
        onRefresh: () async => ref.invalidate(myRequestsProvider),
        child: requests.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (e, _) => ListView(children: [
            const SizedBox(height: 120),
            Center(child: Text('Could not load requests: $e')),
          ]),
          data: (items) {
            if (items.isEmpty) {
              return ListView(children: const [
                SizedBox(height: 120),
                Center(child: Text('You have no access requests')),
              ]);
            }
            return ListView.separated(
              padding: const EdgeInsets.all(12),
              itemCount: items.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (context, i) => _RequestTile(request: items[i]),
            );
          },
        ),
      ),
    );
  }
}

class _RequestTile extends StatelessWidget {
  const _RequestTile({required this.request});
  final AccessRequest request;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        title: Text(request.title,
            style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (request.resource.isNotEmpty) Text(request.resource),
            if (request.requestedAt.isNotEmpty)
              Text('Requested ${request.requestedAt}',
                  style: const TextStyle(fontSize: 12)),
          ],
        ),
        trailing: _StatusBadge(status: request.status),
      ),
    );
  }
}

class _StatusBadge extends StatelessWidget {
  const _StatusBadge({required this.status});
  final String status;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final (color, icon) = switch (status.toLowerCase()) {
      'approved' || 'granted' => (Colors.green, Icons.check_circle),
      'denied' || 'rejected' => (scheme.error, Icons.cancel),
      'expired' => (Colors.grey, Icons.timer_off),
      _ => (Colors.orange, Icons.hourglass_bottom),
    };
    return Chip(
      avatar: Icon(icon, size: 16, color: color),
      label: Text(status, style: TextStyle(fontSize: 12, color: color)),
      visualDensity: VisualDensity.compact,
    );
  }
}
