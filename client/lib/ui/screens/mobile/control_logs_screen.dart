import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:openidx_engine/openidx_engine.dart';

/// In-app viewer for the on-device engine/control log (`control.log`), so users
/// can inspect control-plane activity without adb. Mobile-only: the engine runs
/// in-process via the gomobile plugin, which persists a rolling tail to the app
/// sandbox and mirrors it to logcat.
class ControlLogsScreen extends StatefulWidget {
  const ControlLogsScreen({super.key});

  @override
  State<ControlLogsScreen> createState() => _ControlLogsScreenState();
}

class _ControlLogsScreenState extends State<ControlLogsScreen> {
  final OpenidxEngine _engine = OpenidxEngine();
  late Future<String> _future;

  @override
  void initState() {
    super.initState();
    _future = _load();
  }

  Future<String> _load() async {
    try {
      final s = await _engine.logs();
      return s.trim().isEmpty ? 'No control logs yet.' : s;
    } on Object catch (e) {
      return 'Failed to read control logs: $e';
    }
  }

  void _refresh() => setState(() => _future = _load());

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Control logs'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: _refresh,
          ),
          IconButton(
            icon: const Icon(Icons.copy_all_outlined),
            tooltip: 'Copy',
            onPressed: () async {
              final s = await _future;
              await Clipboard.setData(ClipboardData(text: s));
              if (mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Control logs copied')),
                );
              }
            },
          ),
        ],
      ),
      body: FutureBuilder<String>(
        future: _future,
        builder: (context, snap) {
          if (!snap.hasData) {
            return const Center(child: CircularProgressIndicator());
          }
          return Scrollbar(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(12),
              child: SelectableText(
                snap.data!,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          );
        },
      ),
    );
  }
}
