import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../api/governance.dart';
import '../../../state/mobile_providers.dart';

/// Pending governance approvals inbox. Approve/deny each with an optional
/// comment; the list refreshes after each decision.
class ApprovalsScreen extends ConsumerWidget {
  const ApprovalsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final approvals = ref.watch(myApprovalsProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Approvals')),
      body: RefreshIndicator(
        onRefresh: () async => ref.invalidate(myApprovalsProvider),
        child: approvals.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (e, _) => _Retry(
            message: '$e',
            onRetry: () => ref.invalidate(myApprovalsProvider),
          ),
          data: (items) {
            if (items.isEmpty) {
              return ListView(
                children: const [
                  SizedBox(height: 120),
                  Center(child: Text('No pending approvals')),
                ],
              );
            }
            return ListView.separated(
              padding: const EdgeInsets.all(12),
              itemCount: items.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (context, i) => _ApprovalCard(item: items[i]),
            );
          },
        ),
      ),
    );
  }
}

class _ApprovalCard extends ConsumerStatefulWidget {
  const _ApprovalCard({required this.item});
  final ApprovalItem item;

  @override
  ConsumerState<_ApprovalCard> createState() => _ApprovalCardState();
}

class _ApprovalCardState extends ConsumerState<_ApprovalCard> {
  bool _busy = false;

  Future<void> _decide(bool approve) async {
    final comment = await _promptComment(approve);
    if (comment == null) return; // cancelled
    setState(() => _busy = true);
    try {
      final api = ref.read(governanceApiProvider);
      if (approve) {
        await api.approve(widget.item.id, comment: comment);
      } else {
        await api.deny(widget.item.id, comment: comment);
      }
      ref.invalidate(myApprovalsProvider);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Failed: $e')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<String?> _promptComment(bool approve) {
    final controller = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(approve ? 'Approve request' : 'Deny request'),
        content: TextField(
          controller: controller,
          decoration: const InputDecoration(
            labelText: 'Comment (optional)',
            border: OutlineInputBorder(),
          ),
          maxLines: 3,
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text.trim()),
            child: Text(approve ? 'Approve' : 'Deny'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final item = widget.item;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(item.title,
                      style: const TextStyle(
                          fontSize: 16, fontWeight: FontWeight.w600)),
                ),
                _RiskChip(level: item.riskLevel),
              ],
            ),
            const SizedBox(height: 8),
            if (item.requester.isNotEmpty)
              Text('Requester: ${item.requester}'),
            if (item.resource.isNotEmpty) Text('Resource: ${item.resource}'),
            if (item.reason.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('“${item.reason}”',
                  style: const TextStyle(fontStyle: FontStyle.italic)),
            ],
            const SizedBox(height: 12),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(
                    onPressed: _busy ? null : () => _decide(false),
                    child: const Text('Deny')),
                const SizedBox(width: 8),
                FilledButton(
                    onPressed: _busy ? null : () => _decide(true),
                    child: const Text('Approve')),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _RiskChip extends StatelessWidget {
  const _RiskChip({required this.level});
  final String level;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final color = switch (level.toLowerCase()) {
      'high' || 'critical' => scheme.error,
      'medium' => Colors.orange,
      _ => scheme.primary,
    };
    return Chip(
      label: Text(level, style: TextStyle(color: color, fontSize: 12)),
      side: BorderSide(color: color),
      visualDensity: VisualDensity.compact,
    );
  }
}

class _Retry extends StatelessWidget {
  const _Retry({required this.message, required this.onRetry});
  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    return ListView(
      children: [
        const SizedBox(height: 100),
        const Icon(Icons.error_outline, size: 40),
        const SizedBox(height: 8),
        Center(child: Text(message, textAlign: TextAlign.center)),
        const SizedBox(height: 12),
        Center(
          child: FilledButton.icon(
            onPressed: onRetry,
            icon: const Icon(Icons.refresh),
            label: const Text('Retry'),
          ),
        ),
      ],
    );
  }
}
