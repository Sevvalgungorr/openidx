import 'api_client.dart';

/// Notifications endpoints (identity service): list, mark-read, and the push
/// configuration used to register this device for delivery.
class NotificationsApi {
  NotificationsApi(this._api);
  final ApiClient _api;

  /// `GET /api/v1/identity/notifications`.
  Future<List<AppNotification>> list() async {
    final json = await _api.get<dynamic>('/api/v1/identity/notifications');
    final raw = json is Map<String, dynamic>
        ? (json['items'] ?? json['notifications'] ?? json['data'])
        : json;
    if (raw is! List) return const [];
    return raw
        .whereType<Map<String, dynamic>>()
        .map(AppNotification.fromJson)
        .toList(growable: false);
  }

  /// `POST /api/v1/identity/notifications/mark-read`.
  ///
  /// Pass specific [ids] to mark a subset, or omit to mark all read.
  Future<void> markRead({List<String>? ids}) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/identity/notifications/mark-read',
      data: {
        if (ids != null) 'ids': ids else 'all': true,
      },
    );
  }

  /// `GET /api/v1/identity/notifications/push-config` — provider keys/topics for
  /// registering the device with the push service.
  Future<PushConfig> pushConfig() async {
    final json = await _api.get<Map<String, dynamic>>(
      '/api/v1/identity/notifications/push-config',
    );
    return PushConfig.fromJson(json);
  }
}

class AppNotification {
  const AppNotification({
    required this.id,
    required this.title,
    required this.body,
    required this.category,
    required this.read,
    required this.createdAt,
    required this.deepLink,
  });
  final String id;
  final String title;
  final String body;
  final String category;
  final bool read;
  final String createdAt;

  /// Optional `openidx://…` target to route to on tap.
  final String deepLink;

  factory AppNotification.fromJson(Map<String, dynamic> j) => AppNotification(
        id: (j['id'] ?? '') as String,
        title: (j['title'] ?? '') as String,
        body: (j['body'] ?? j['message'] ?? '') as String,
        category: (j['category'] ?? j['type'] ?? '') as String,
        read: (j['read'] ?? j['is_read'] ?? false) as bool,
        createdAt: (j['created_at'] ?? '') as String,
        deepLink: (j['deep_link'] ?? j['link'] ?? '') as String,
      );
}

class PushConfig {
  const PushConfig({
    required this.provider,
    required this.senderId,
    required this.topic,
  });
  final String provider;
  final String senderId;
  final String topic;

  factory PushConfig.fromJson(Map<String, dynamic> j) => PushConfig(
        provider: (j['provider'] ?? '') as String,
        senderId: (j['sender_id'] ?? j['fcm_sender_id'] ?? '') as String,
        topic: (j['topic'] ?? '') as String,
      );
}
