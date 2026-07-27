import { Stack } from 'expo-router';
import * as LocalAuthentication from 'expo-local-authentication';
import { useCallback, useEffect, useRef, useState } from 'react';
import { AppState, Pressable, StyleSheet, Text, View } from 'react-native';

// Grace period: don't re-prompt for a brief app-switch (notification shade, a
// quick jump to another app to copy a code, an OAuth round-trip). Banking apps
// and 1Password all use an idle window rather than locking on every blur. Should
// become a user setting (Immediately / 1 min / 5 min); 60s is a sane default.
const LOCK_GRACE_MS = 60_000;

/**
 * Biometric app-lock: requires Face ID / Touch ID / fingerprint — with the
 * device passcode as fallback — on cold start and when the app returns to the
 * foreground after being away longer than the grace period. No-ops on devices
 * without any biometric/passcode so it never bricks access (a "set a device
 * lock" nudge belongs in the security screen, tied to the screen_lock posture
 * check).
 *
 * This is a PRESENCE assertion over the already-established OpenIDX session, not
 * the login itself (OWASP MASVS V4.5). The session/token still comes from the
 * OAuth/passkey flow.
 */
function useAppLock() {
  const [locked, setLocked] = useState(true);
  const [checking, setChecking] = useState(false);
  const enabledRef = useRef<boolean | null>(null);
  // Timestamp the app last went to the background; used for the grace window.
  const backgroundedAt = useRef<number>(0);

  const isEnabled = useCallback(async () => {
    if (enabledRef.current === null) {
      const hw = await LocalAuthentication.hasHardwareAsync();
      const enrolled = await LocalAuthentication.isEnrolledAsync();
      enabledRef.current = hw && enrolled;
    }
    return enabledRef.current;
  }, []);

  const unlock = useCallback(async () => {
    if (checking) return;
    setChecking(true);
    try {
      if (!(await isEnabled())) {
        // No biometric/passcode enrolled — do not block access, but the app
        // should nudge the user to enable a device lock elsewhere.
        setLocked(false);
        return;
      }
      const r = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Unlock OpenIDX',
        // Fall back to the device passcode when biometric fails or is
        // unavailable, instead of dead-ending on a failed face/finger scan.
        disableDeviceFallback: false,
        fallbackLabel: 'Use passcode',
      });
      setLocked(!r.success);
    } finally {
      setChecking(false);
    }
  }, [checking, isEnabled]);

  useEffect(() => {
    // Cold start always locks.
    unlock();
    const sub = AppState.addEventListener('change', (s) => {
      if (s === 'background' || s === 'inactive') {
        backgroundedAt.current = Date.now();
      } else if (s === 'active') {
        // Only re-lock if we were away longer than the grace period.
        const away = Date.now() - backgroundedAt.current;
        if (backgroundedAt.current === 0 || away > LOCK_GRACE_MS) {
          setLocked(true);
          unlock();
        }
      }
    });
    return () => sub.remove();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { locked, unlock, checking };
}

export default function AppLayout() {
  const { locked, unlock, checking } = useAppLock();

  if (locked) {
    return (
      <View style={styles.lock}>
        <Text style={styles.lockTitle}>OpenIDX is locked</Text>
        <Pressable style={styles.unlock} onPress={unlock} disabled={checking}>
          <Text style={styles.unlockText}>
            {checking ? 'Authenticating…' : 'Unlock'}
          </Text>
        </Pressable>
      </View>
    );
  }
  return <Stack screenOptions={{ headerShown: true }} />;
}

const styles = StyleSheet.create({
  lock: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 20, padding: 24 },
  lockTitle: { fontSize: 20, fontWeight: '700' },
  unlock: {
    height: 52,
    paddingHorizontal: 40,
    borderRadius: 14,
    backgroundColor: '#208AEF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  unlockText: { color: 'white', fontSize: 17, fontWeight: '600' },
});
