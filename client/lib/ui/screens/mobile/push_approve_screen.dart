import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../api/mfa.dart';
import '../../../state/mobile_providers.dart';

/// Number-match push approval. Reached via the `openidx://approve/<challengeId>`
/// deep link (or a push tap). Shows the sign-in context and three numbers; the
/// user taps the number the login screen displays to approve — or denies /
/// reports as fraud. Backed by the push verify endpoint.
class PushApproveScreen extends ConsumerStatefulWidget {
  const PushApproveScreen({super.key, required this.challengeId});

  final String challengeId;

  @override
  ConsumerState<PushApproveScreen> createState() => _PushApproveScreenState();
}

class _PushApproveScreenState extends ConsumerState<PushApproveScreen> {
  late Future<PushChallenge> _challenge;
  bool _submitting = false;

  @override
  void initState() {
    super.initState();
    _challenge =
        ref.read(mfaApiProvider).pushChallenge(widget.challengeId);
  }

  Future<void> _decide(PushDecision decision, {int? number}) async {
    setState(() => _submitting = true);
    try {
      await ref.read(mfaApiProvider).pushVerify(
            challengeId: widget.challengeId,
            decision: decision,
            selectedNumber: number,
          );
      if (!mounted) return;
      final label = switch (decision) {
        PushDecision.approve => 'Approved',
        PushDecision.deny => 'Denied',
        PushDecision.report => 'Reported as fraud',
      };
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(label)));
      Navigator.of(context).maybePop();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Failed: $e')));
      }
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Approve sign-in')),
      body: FutureBuilder<PushChallenge>(
        future: _challenge,
        builder: (context, snap) {
          if (snap.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snap.hasError) {
            return Center(child: Text('Could not load challenge: ${snap.error}'));
          }
          final c = snap.data!;
          return _body(context, c);
        },
      ),
    );
  }

  Widget _body(BuildContext context, PushChallenge c) {
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _contextCard(context, c),
          const SizedBox(height: 24),
          const Text('Tap the number shown on your other device',
              textAlign: TextAlign.center),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              for (final n in c.numbers)
                _NumberButton(
                  number: n,
                  enabled: !_submitting,
                  onTap: () => _decide(PushDecision.approve, number: n),
                ),
            ],
          ),
          const Spacer(),
          OutlinedButton.icon(
            onPressed: _submitting ? null : () => _decide(PushDecision.deny),
            icon: const Icon(Icons.close),
            label: const Text('It wasn’t me — Deny'),
          ),
          const SizedBox(height: 8),
          TextButton.icon(
            onPressed: _submitting ? null : () => _decide(PushDecision.report),
            icon: const Icon(Icons.report_gmailerrorred),
            label: const Text('Report as fraud'),
          ),
        ],
      ),
    );
  }

  Widget _contextCard(BuildContext context, PushChallenge c) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(c.appName.isEmpty ? 'Sign-in request' : c.appName,
                style: const TextStyle(
                    fontSize: 18, fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            if (c.location.isNotEmpty) _kv(Icons.place_outlined, c.location),
            if (c.ipAddress.isNotEmpty) _kv(Icons.wifi, c.ipAddress),
            if (c.requestedAt.isNotEmpty)
              _kv(Icons.schedule, c.requestedAt),
          ],
        ),
      ),
    );
  }

  Widget _kv(IconData icon, String value) => Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Row(children: [
          Icon(icon, size: 16),
          const SizedBox(width: 8),
          Expanded(child: Text(value)),
        ]),
      );
}

class _NumberButton extends StatelessWidget {
  const _NumberButton({
    required this.number,
    required this.enabled,
    required this.onTap,
  });

  final int number;
  final bool enabled;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 80,
      height: 80,
      child: FilledButton.tonal(
        onPressed: enabled ? onTap : null,
        child: Text('$number', style: const TextStyle(fontSize: 28)),
      ),
    );
  }
}
