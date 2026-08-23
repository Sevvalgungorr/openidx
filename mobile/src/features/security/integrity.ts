/**
 * Best-effort device-integrity signal for the app UI.
 *
 * A rooted / jailbroken device can read another app's keystore-protected data
 * and hook the runtime, so an authenticator on such a device is materially less
 * trustworthy. We CANNOT hard-block (Expo/JS can't reliably detect a determined
 * jailbreak, and blocking legitimate users on false positives is worse), but we
 * surface a clear warning so the user — and, via posture reporting, the admin —
 * knows. Enforcement (e.g. denying high-risk access) stays a backend decision
 * driven by the posture report, never a client-only gate.
 *
 * Signals used:
 *  - expo-device isRootedExperimentalAsync (Android-focused, best effort)
 *  - not running on a physical device (emulator/simulator) — a weak but useful
 *    secondary signal that the environment isn't a normal user's phone.
 */
import * as Device from 'expo-device';

export type IntegrityStatus = {
  /** true only when we have positive evidence of compromise. */
  compromised: boolean;
  /** true when running on an emulator/simulator rather than a physical device. */
  emulator: boolean;
  /** null when the root/jailbreak check could not run (unknown, not "clean"). */
  rooted: boolean | null;
};

export async function checkDeviceIntegrity(): Promise<IntegrityStatus> {
  let rooted: boolean | null = null;
  try {
    rooted = await Device.isRootedExperimentalAsync();
  } catch {
    rooted = null;
  }
  // Device.isDevice is false on simulators/emulators.
  const emulator = Device.isDevice === false;
  return {
    rooted,
    emulator,
    compromised: rooted === true,
  };
}

/** A short user-facing warning, or null when nothing to warn about. */
export function integrityWarning(s: IntegrityStatus): string | null {
  if (s.compromised) {
    return 'This device appears to be rooted or jailbroken. Your codes and sign-in are less secure here; avoid using it for sensitive accounts.';
  }
  if (s.emulator) {
    return 'Running on an emulator/simulator. Keystore protection is weaker than on a real device.';
  }
  return null;
}
