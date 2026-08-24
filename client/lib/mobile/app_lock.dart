import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:local_auth/local_auth.dart';

/// Biometric app-lock state: locked on cold start and after the app has been
/// backgrounded past an idle threshold. Unlocks via Face ID / Touch ID /
/// fingerprint, with a graceful fallback when no biometrics are enrolled
/// (device passcode, or — if the device has no secure lock at all — no lock).
class AppLockState {
  const AppLockState({required this.locked, required this.available});
  final bool locked;

  /// Whether any local authentication (biometric or device credential) exists.
  final bool available;

  AppLockState copyWith({bool? locked, bool? available}) => AppLockState(
        locked: locked ?? this.locked,
        available: available ?? this.available,
      );
}

class AppLockController extends StateNotifier<AppLockState> {
  AppLockController({
    LocalAuthentication? auth,
    this.idleTimeout = const Duration(minutes: 2),
  })  : _auth = auth ?? LocalAuthentication(),
        super(const AppLockState(locked: true, available: false)) {
    _init();
  }

  final LocalAuthentication _auth;
  final Duration idleTimeout;
  DateTime? _backgroundedAt;

  Future<void> _init() async {
    final supported = await _isSupported();
    // If the device offers no secure lock, don't trap the user out.
    state = state.copyWith(available: supported, locked: supported);
    if (supported) {
      await unlock();
    }
  }

  Future<bool> _isSupported() async {
    try {
      final canCheck = await _auth.canCheckBiometrics;
      final supported = await _auth.isDeviceSupported();
      return canCheck || supported;
    } on Object {
      return false;
    }
  }

  /// Prompt for biometrics/device credential. On success, unlock.
  Future<bool> unlock() async {
    if (!state.available) {
      state = state.copyWith(locked: false);
      return true;
    }
    try {
      final ok = await _auth.authenticate(
        localizedReason: 'Unlock OpenIDX',
        options: const AuthenticationOptions(
          biometricOnly: false,
          stickyAuth: true,
        ),
      );
      if (ok) state = state.copyWith(locked: false);
      return ok;
    } on Object {
      return false;
    }
  }

  /// Call from `didChangeAppLifecycleState`. Records background time; on resume
  /// re-locks if idle longer than [idleTimeout].
  void onLifecycle(AppLifecycleState lifecycle) {
    if (!state.available) return;
    if (lifecycle == AppLifecycleState.paused ||
        lifecycle == AppLifecycleState.inactive) {
      _backgroundedAt ??= DateTime.now();
    } else if (lifecycle == AppLifecycleState.resumed) {
      final since = _backgroundedAt;
      _backgroundedAt = null;
      if (since != null && DateTime.now().difference(since) >= idleTimeout) {
        state = state.copyWith(locked: true);
      }
    }
  }
}

final appLockProvider =
    StateNotifierProvider<AppLockController, AppLockState>((ref) {
  return AppLockController();
});

/// Wraps [child] with a blocking lock overlay while the app is locked.
///
/// Also bridges app-lifecycle events into the controller so idle re-locking
/// works. Place it just under the mobile shell.
class AppLockGate extends ConsumerStatefulWidget {
  const AppLockGate({super.key, required this.child});
  final Widget child;

  @override
  ConsumerState<AppLockGate> createState() => _AppLockGateState();
}

class _AppLockGateState extends ConsumerState<AppLockGate>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    ref.read(appLockProvider.notifier).onLifecycle(state);
  }

  @override
  Widget build(BuildContext context) {
    final lock = ref.watch(appLockProvider);
    return Stack(
      children: [
        widget.child,
        if (lock.locked) _LockOverlay(onUnlock: () {
          ref.read(appLockProvider.notifier).unlock();
        }),
      ],
    );
  }
}

class _LockOverlay extends StatelessWidget {
  const _LockOverlay({required this.onUnlock});
  final VoidCallback onUnlock;

  @override
  Widget build(BuildContext context) {
    return Positioned.fill(
      child: Material(
        color: Theme.of(context).colorScheme.surface,
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.lock_outline, size: 56),
              const SizedBox(height: 16),
              const Text('OpenIDX is locked',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: onUnlock,
                icon: const Icon(Icons.fingerprint),
                label: const Text('Unlock'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
