/**
 * Token storage backed by the OS keystore (iOS Keychain / Android Keystore) via
 * expo-secure-store. Replaces the web console's localStorage token handling.
 */
import * as SecureStore from 'expo-secure-store';

const ACCESS = 'oidx.access_token';
const REFRESH = 'oidx.refresh_token';
const EXP = 'oidx.token_exp'; // unix seconds
const ORG_SLUG = 'oidx.org_slug';

// Write options applied to every stored secret. WHEN_UNLOCKED_THIS_DEVICE_ONLY:
//   - the item is readable only while the device is unlocked (not from the lock
//     screen or a background task on a locked phone), and
//   - THIS_DEVICE_ONLY keeps it out of iCloud Keychain / device-to-device
//     migration and encrypted backups, so tokens can't be lifted off a backup
//     or restored onto another device.
const STORE_OPTS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export type Tokens = {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number; // unix seconds
};

export async function getAccessToken(): Promise<string | null> {
  return SecureStore.getItemAsync(ACCESS, STORE_OPTS);
}

export async function getRefreshToken(): Promise<string | null> {
  return SecureStore.getItemAsync(REFRESH, STORE_OPTS);
}

export async function getExpiresAt(): Promise<number> {
  const v = await SecureStore.getItemAsync(EXP, STORE_OPTS);
  return v ? Number(v) : 0;
}

export async function setTokens(t: Tokens): Promise<void> {
  await SecureStore.setItemAsync(ACCESS, t.accessToken, STORE_OPTS);
  await SecureStore.setItemAsync(EXP, String(t.expiresAt), STORE_OPTS);
  if (t.refreshToken) {
    await SecureStore.setItemAsync(REFRESH, t.refreshToken, STORE_OPTS);
  }
}

export async function clearTokens(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(ACCESS),
    SecureStore.deleteItemAsync(REFRESH),
    SecureStore.deleteItemAsync(EXP),
  ]);
}

export async function getOrgSlug(): Promise<string | null> {
  return SecureStore.getItemAsync(ORG_SLUG, STORE_OPTS);
}

export async function setOrgSlug(slug: string | null): Promise<void> {
  if (slug) await SecureStore.setItemAsync(ORG_SLUG, slug, STORE_OPTS);
  else await SecureStore.deleteItemAsync(ORG_SLUG);
}
