import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../api/notifications.dart';
import '../../../state/mobile_providers.dart';

/// Notification inbox: list with unread markers and a mark-all-read action.
class NotificationsScreen extends ConsumerWidget {
  const NotificationsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final notifications = ref.watch(notificationsProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Notifications'),
        actions: [
          IconButton(
            tooltip: 'Mark all read',
            icon: const Icon(Icons.mark_email_read_outlined),
            onPressed: () async {
              await ref.read(notificationsApiProvider).markRead();
              ref.invalidate(notificationsProvider);
            },
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: () async => ref.invalidate(notificationsProvider),
        child: notifications.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (e, _) => ListView(children: [
            const SizedBox(height: 120),
            Center(child: Text('Could not load notifications: $e')),
          ]),
          data: (items) {
            if (items.isEmpty) {
              return ListView(children: const [
                SizedBox(height: 120),
                Center(child: Text('You’re all caught up')),
              ]);
            }
            return ListView.separated(
              itemCount: items.length,
              separatorBuilder: (_, __) => const Divider(height: 1),
              itemBuilder: (context, i) => _NotificationTile(
                notification: items[i],
                onTap: () async {
                  await ref
                      .read(notificationsApiProvider)
                      .markRead(ids: [items[i].id]);
                  ref.invalidate(notificationsProvider);
                },
              ),
            );
          },
        ),
      ),
    );
  }
}

class _NotificationTile extends StatelessWidget {
  const _NotificationTile({required this.notification, required this.onTap});
  final AppNotification notification;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Icon(
        notification.read
            ? Icons.notifications_none
            : Icons.notifications_active,
        color: notification.read
            ? Theme.of(context).disabledColor
            : Theme.of(context).colorScheme.primary,
      ),
      title: Text(
        notification.title,
        style: TextStyle(
          fontWeight:
              notification.read ? FontWeight.normal : FontWeight.w600,
        ),
      ),
      subtitle: Text(notification.body),
      trailing: notification.createdAt.isEmpty
          ? null
          : Text(notification.createdAt,
              style: const TextStyle(fontSize: 11)),
      onTap: onTap,
    );
  }
}
