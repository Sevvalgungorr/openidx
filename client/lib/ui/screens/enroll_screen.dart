import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../state/providers.dart';

/// Shown when the device is not yet enrolled. The user pastes an enrollment
/// code, which the engine exchanges via `/enroll`.
class EnrollScreen extends ConsumerStatefulWidget {
  const EnrollScreen({super.key});

  @override
  ConsumerState<EnrollScreen> createState() => _EnrollScreenState();
}

class _EnrollScreenState extends ConsumerState<EnrollScreen> {
  final _controller = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _enroll() async {
    final code = _controller.text.trim();
    if (code.isEmpty) {
      setState(() => _error = 'Enter an enrollment code.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(engineActionsProvider).enroll(code);
      // Status refresh drives the router to the login screen.
    } on Object catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.qr_code_2, size: 56),
                const SizedBox(height: 16),
                Text(
                  'Enroll this device',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 8),
                Text(
                  'Enter the enrollment code from your OpenIDX admin console.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 24),
                TextField(
                  controller: _controller,
                  autofocus: true,
                  enabled: !_busy,
                  decoration: const InputDecoration(
                    labelText: 'Enrollment code',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.vpn_key_outlined),
                  ),
                  onSubmitted: (_) => _enroll(),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: _busy ? null : _enroll,
                  icon: _busy
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.check),
                  label: const Text('Enroll'),
                ),
                if (_error != null) ...[
                  const SizedBox(height: 16),
                  Text(
                    _error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                      fontSize: 13,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
