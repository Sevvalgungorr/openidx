import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../features/totp.dart';
import '../../../state/mobile_providers.dart';

/// Offline TOTP authenticator: the user's saved accounts with live 6-digit
/// codes and a per-period countdown ring. Secrets never leave the device;
/// codes are generated in Dart (`features/totp.dart`). Adding an account
/// accepts a pasted `otpauth://` URI (QR scan is a TODO — see [_AddSheet]).
class AuthenticatorScreen extends ConsumerStatefulWidget {
  const AuthenticatorScreen({super.key});

  @override
  ConsumerState<AuthenticatorScreen> createState() =>
      _AuthenticatorScreenState();
}

class _AuthenticatorScreenState extends ConsumerState<AuthenticatorScreen> {
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    // Rebuild every second to advance codes + countdown.
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _ticker?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final accounts = ref.watch(authenticatorProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Codes')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _openAdd,
        icon: const Icon(Icons.add),
        label: const Text('Add'),
      ),
      body: accounts.isEmpty
          ? const _EmptyCodes()
          : ListView.separated(
              padding: const EdgeInsets.all(12),
              itemCount: accounts.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (context, i) => _CodeTile(account: accounts[i]),
            ),
    );
  }

  Future<void> _openAdd() async {
    final uri = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      builder: (_) => const _AddSheet(),
    );
    if (uri == null || uri.isEmpty) return;
    try {
      await ref.read(authenticatorProvider.notifier).addFromUri(uri);
    } on FormatException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Invalid otpauth URI: ${e.message}')),
        );
      }
    }
  }
}

class _CodeTile extends ConsumerWidget {
  const _CodeTile({required this.account});
  final OtpAccount account;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final code = account.code();
    final remaining = Totp.secondsRemaining(periodSeconds: account.period);
    final progress = remaining / account.period;
    final display = code.length > 3
        ? '${code.substring(0, code.length ~/ 2)} ${code.substring(code.length ~/ 2)}'
        : code;

    return Card(
      child: ListTile(
        title: Text(
          account.issuer.isNotEmpty ? account.issuer : account.account,
          style: const TextStyle(fontWeight: FontWeight.w600),
        ),
        subtitle: Text(account.account),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              display,
              style: const TextStyle(
                fontSize: 22,
                fontFeatures: [FontFeature.tabularFigures()],
                letterSpacing: 1.5,
              ),
            ),
            const SizedBox(width: 12),
            SizedBox(
              width: 28,
              height: 28,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  CircularProgressIndicator(value: progress, strokeWidth: 3),
                  Text('$remaining', style: const TextStyle(fontSize: 11)),
                ],
              ),
            ),
          ],
        ),
        onTap: () {
          Clipboard.setData(ClipboardData(text: code));
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Code copied')),
          );
        },
        onLongPress: () => _confirmRemove(context, ref),
      ),
    );
  }

  Future<void> _confirmRemove(BuildContext context, WidgetRef ref) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Remove account?'),
        content: Text('${account.issuer} (${account.account})'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Remove')),
        ],
      ),
    );
    if (ok == true) {
      await ref.read(authenticatorProvider.notifier).remove(account.id);
    }
  }
}

class _AddSheet extends StatefulWidget {
  const _AddSheet();

  @override
  State<_AddSheet> createState() => _AddSheetState();
}

class _AddSheetState extends State<_AddSheet> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final insets = MediaQuery.of(context).viewInsets;
    return Padding(
      padding: EdgeInsets.fromLTRB(16, 16, 16, 16 + insets.bottom),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text('Add account',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
          const SizedBox(height: 12),
          TextField(
            controller: _controller,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: 'otpauth:// URI',
              hintText: 'otpauth://totp/Issuer:you@example.com?secret=…',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          // TODO(phase-2b): QR scan via `mobile_scanner` to fill this field.
          const Align(
            alignment: Alignment.centerLeft,
            child: Text('QR scanning coming soon — paste the URI for now.',
                style: TextStyle(fontSize: 12)),
          ),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: () => Navigator.pop(context, _controller.text.trim()),
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }
}

class _EmptyCodes extends StatelessWidget {
  const _EmptyCodes();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.qr_code_2, size: 48),
          SizedBox(height: 12),
          Text('No authenticator accounts yet'),
          SizedBox(height: 4),
          Text('Tap Add to paste an otpauth:// URI',
              style: TextStyle(fontSize: 12)),
        ],
      ),
    );
  }
}
