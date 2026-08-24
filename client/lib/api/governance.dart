import 'api_client.dart';

/// Governance endpoints: the user's pending approvals and their own access
/// requests. Mirrors the RN app's approvals/my-access journeys.
class GovernanceApi {
  GovernanceApi(this._api);
  final ApiClient _api;

  /// `GET /api/v1/governance/my-approvals` — items awaiting this user's action.
  Future<List<ApprovalItem>> myApprovals() async {
    final json = await _api.get<dynamic>('/api/v1/governance/my-approvals');
    return _list(json).map(ApprovalItem.fromJson).toList(growable: false);
  }

  /// `POST /api/v1/governance/requests/{id}/approve`.
  Future<void> approve(String requestId, {String? comment}) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/governance/requests/$requestId/approve',
      data: {if (comment != null) 'comment': comment},
    );
  }

  /// `POST /api/v1/governance/requests/{id}/deny`.
  Future<void> deny(String requestId, {String? comment}) async {
    await _api.post<Map<String, dynamic>>(
      '/api/v1/governance/requests/$requestId/deny',
      data: {if (comment != null) 'comment': comment},
    );
  }

  /// `GET /api/v1/governance/requests?requester_id=me` — the user's own
  /// requests (my-access).
  Future<List<AccessRequest>> myRequests() async {
    final json = await _api.get<dynamic>(
      '/api/v1/governance/requests',
      query: {'requester_id': 'me'},
    );
    return _list(json).map(AccessRequest.fromJson).toList(growable: false);
  }

  List<Map<String, dynamic>> _list(dynamic json) {
    final raw = json is Map<String, dynamic>
        ? (json['items'] ?? json['requests'] ?? json['data'])
        : json;
    if (raw is List) {
      return raw.whereType<Map<String, dynamic>>().toList(growable: false);
    }
    return const [];
  }
}

class ApprovalItem {
  const ApprovalItem({
    required this.id,
    required this.title,
    required this.requester,
    required this.resource,
    required this.reason,
    required this.requestedAt,
    required this.riskLevel,
  });
  final String id;
  final String title;
  final String requester;
  final String resource;
  final String reason;
  final String requestedAt;
  final String riskLevel;

  factory ApprovalItem.fromJson(Map<String, dynamic> j) => ApprovalItem(
        id: (j['id'] ?? j['request_id'] ?? '') as String,
        title: (j['title'] ?? j['name'] ?? 'Access request') as String,
        requester: (j['requester'] ?? j['requester_name'] ?? '') as String,
        resource: (j['resource'] ?? j['resource_name'] ?? '') as String,
        reason: (j['reason'] ?? j['justification'] ?? '') as String,
        requestedAt: (j['requested_at'] ?? j['created_at'] ?? '') as String,
        riskLevel: (j['risk_level'] ?? j['risk'] ?? 'unknown') as String,
      );
}

class AccessRequest {
  const AccessRequest({
    required this.id,
    required this.title,
    required this.status,
    required this.resource,
    required this.requestedAt,
  });
  final String id;
  final String title;
  final String status;
  final String resource;
  final String requestedAt;

  factory AccessRequest.fromJson(Map<String, dynamic> j) => AccessRequest(
        id: (j['id'] ?? j['request_id'] ?? '') as String,
        title: (j['title'] ?? j['name'] ?? 'Access request') as String,
        status: (j['status'] ?? 'pending') as String,
        resource: (j['resource'] ?? j['resource_name'] ?? '') as String,
        requestedAt: (j['requested_at'] ?? j['created_at'] ?? '') as String,
      );
}
