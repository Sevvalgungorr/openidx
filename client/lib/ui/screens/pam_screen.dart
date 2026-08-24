import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../engine/models.dart';
import '../../state/providers.dart';

/// Lists PAM entries. Each entry can be connected (opens the launch URL via
/// url_launcher) or, when approval is required, a request can be submitted.
class PamScreen extends ConsumerWidget {
  const PamScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final entriesAsync = ref.watch(pamEntriesProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Privileged Access'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh),
            onPressed: () => ref.invalidate(pamEntriesProvider),
          ),
        ],
      ),
      body: entriesAsync.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Text('Failed to load entries: $e'),
          ),
        ),
        data: (entries) {
          if (entries.isEmpty) {
            return const Center(child: Text('No PAM entries available.'));
          }
          return ListView.separated(
            padding: const EdgeInsets.all(12),
            itemCount: entries.length,
            separatorBuilder: (_, __) => const SizedBox(height: 8),
            itemBuilder: (_, i) => _PamTile(entry: entries[i]),
          );
        },
      ),
    );
  }
}

class _PamTile extends ConsumerStatefulWidget {
  const _PamTile({required this.entry});

  final PamEntry entry;

  @override
  ConsumerState<_PamTile> createState() => _PamTileState();
}

class _PamTileState extends ConsumerState<_PamTile> {
  bool _busy = false;

  Future<void> _connect() async {
    setState(() => _busy = true);
    try {
      final result =
          await ref.read(engineActionsProvider).pamConnect(widget.entry.id);
      final target = result.launchTarget;
      if (target.isEmpty) {
        _snack('Engine returned no launch URL.');
        return;
      }
      final uri = Uri.parse(target);
      final ok = await launchUrl(uri, mode: LaunchMode.externalApplication);
      if (!ok) _snack('Could not open $target');
    } on Object catch (e) {
      _snack('Connect failed: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _requestAccess() async {
    final reason = await _promptReason();
    if (reason == null) return;
    setState(() => _busy = true);
    try {
      await ref
          .read(engineActionsProvider)
          .pamRequest(widget.entry.id, reason);
      _snack('Access request submitted.');
    } on Object catch (e) {
      _snack('Request failed: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<String?> _promptReason() async {
    final controller = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Request access'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(
            labelText: 'Reason',
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(controller.text.trim()),
            child: const Text('Submit'),
          ),
        ],
      ),
    );
  }

  void _snack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    final e = widget.entry;
    final subtitleParts = <String>[
      e.entryType,
      if (e.hostname.isNotEmpty) '${e.hostname}:${e.port}',
      if (e.reachMode.isNotEmpty) e.reachMode,
    ];

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            const Icon(Icons.dns_outlined),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    e.name,
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    subtitleParts.join(' · '),
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  if (e.requireApproval || e.recordSession)
                    Padding(
                      padding: const EdgeInsets.only(top: 6),
                      child: Wrap(
                        spacing: 6,
                        children: [
                          if (e.requireApproval)
                            const _Badge('Approval required'),
                          if (e.recordSession) const _Badge('Recorded'),
                        ],
                      ),
                    ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            if (_busy)
              const SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            else if (e.requireApproval)
              OutlinedButton(
                onPressed: _requestAccess,
                child: const Text('Request'),
              )
            else
              FilledButton(
                onPressed: _connect,
                child: const Text('Connect'),
              ),
          ],
        ),
      ),
    );
  }
}

class _Badge extends StatelessWidget {
  const _Badge(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.secondaryContainer,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Text(
        text,
        style: Theme.of(context).textTheme.labelSmall,
      ),
    );
  }
}
