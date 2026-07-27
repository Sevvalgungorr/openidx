/**
 * Persistence for the on-device authenticator. Every account's secret is held
 * in the OS keystore (iOS Keychain / Android Keystore) via expo-secure-store —
 * the same at-rest encryption the app already uses for OAuth tokens — so the
 * TOTP secrets never touch plaintext storage and never leave the device.
 *
 * Layout: an index key lists the account ids; each account is a separate
 * keystore entry (keeps every value well under the iOS 2 KB per-item limit).
 */
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';

import type { OtpAccount } from './otp';

const INDEX_KEY = 'oidx.authenticator.index';
const ACCT_PREFIX = 'oidx.authenticator.acct.';

async function readIndex(): Promise<string[]> {
  const raw = await SecureStore.getItemAsync(INDEX_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

async function writeIndex(ids: string[]): Promise<void> {
  await SecureStore.setItemAsync(INDEX_KEY, JSON.stringify(ids));
}

/** All stored accounts, newest first. Corrupt/missing entries are skipped. */
export async function listAccounts(): Promise<OtpAccount[]> {
  const ids = await readIndex();
  const accounts: OtpAccount[] = [];
  for (const id of ids) {
    const raw = await SecureStore.getItemAsync(ACCT_PREFIX + id);
    if (!raw) continue;
    try {
      accounts.push(JSON.parse(raw) as OtpAccount);
    } catch {
      // ignore a corrupt entry rather than break the whole list
    }
  }
  accounts.sort((a, b) => b.createdAt - a.createdAt);
  return accounts;
}

/** Add an account (secret already validated by the caller). Returns its id. */
export async function addAccount(
  input: Omit<OtpAccount, 'id' | 'createdAt'>
): Promise<OtpAccount> {
  const id = Crypto.randomUUID();
  const account: OtpAccount = { ...input, id, createdAt: Date.now() };
  await SecureStore.setItemAsync(ACCT_PREFIX + id, JSON.stringify(account));
  const ids = await readIndex();
  ids.push(id);
  await writeIndex(ids);
  return account;
}

/** Remove an account and its secret from the keystore. */
export async function deleteAccount(id: string): Promise<void> {
  await SecureStore.deleteItemAsync(ACCT_PREFIX + id);
  const ids = await readIndex();
  await writeIndex(ids.filter((x) => x !== id));
}

/** Persist a mutated account (used to advance an HOTP counter). */
export async function updateAccount(account: OtpAccount): Promise<void> {
  await SecureStore.setItemAsync(ACCT_PREFIX + account.id, JSON.stringify(account));
}
