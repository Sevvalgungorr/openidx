/**
 * Lightweight, persisted user preferences for the mobile app — the settings the
 * Settings screen edits. Stored in the OS keystore via expo-secure-store (same
 * at-rest protection as tokens); values are small and non-secret but keeping one
 * storage layer avoids pulling in AsyncStorage.
 *
 * These are read at module boundaries (e.g. the app-lock grace window) rather
 * than through React state, so a plain get/set with an in-memory cache is enough.
 */
import * as SecureStore from 'expo-secure-store';

/** How long the app may stay in the background before it re-locks. */
export type LockTimeout = 'immediately' | '1m' | '5m';

export interface AppSettings {
  /** Biometric app-lock re-prompt window. Default: 1 minute. */
  lockTimeout: LockTimeout;
  /** Hide the codes on the list until tapped (privacy). Default: false. */
  hideCodes: boolean;
  /** Copy a code on single tap (vs. requiring the detail screen). Default: true. */
  tapToCopy: boolean;
}

export const DEFAULT_SETTINGS: AppSettings = {
  lockTimeout: '1m',
  hideCodes: false,
  tapToCopy: true,
};

const KEY = 'oidx.app_settings';

let cache: AppSettings | null = null;

/** Read settings (cached after first load), falling back to defaults. */
export async function getSettings(): Promise<AppSettings> {
  if (cache) return cache;
  const raw = await SecureStore.getItemAsync(KEY);
  if (!raw) {
    cache = { ...DEFAULT_SETTINGS };
    return cache;
  }
  try {
    cache = { ...DEFAULT_SETTINGS, ...(JSON.parse(raw) as Partial<AppSettings>) };
  } catch {
    cache = { ...DEFAULT_SETTINGS };
  }
  return cache;
}

/** Merge and persist a partial settings update; returns the new full settings. */
export async function updateSettings(patch: Partial<AppSettings>): Promise<AppSettings> {
  const current = await getSettings();
  const next = { ...current, ...patch };
  cache = next;
  await SecureStore.setItemAsync(KEY, JSON.stringify(next));
  return next;
}

/** The lock-timeout preference in milliseconds (0 = lock immediately). */
export function lockTimeoutMs(t: LockTimeout): number {
  switch (t) {
    case 'immediately':
      return 0;
    case '5m':
      return 5 * 60_000;
    case '1m':
    default:
      return 60_000;
  }
}
