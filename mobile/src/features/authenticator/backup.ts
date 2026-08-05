/**
 * Encrypted export / import of the on-device authenticator accounts — the
 * "back up my codes" feature (Authy/Google/Okta parity) so a lost or replaced
 * phone doesn't mean re-enrolling every 2FA account.
 *
 * Design goals:
 *  - No new native crypto dependency. We reuse the vetted pure-JS SHA-256/HMAC
 *    already in ./crypto (the same code that drives TOTP) and expo-crypto only
 *    for cryptographically-secure random bytes.
 *  - Passphrase-based: the backup blob is useless without the user's passphrase.
 *  - Authenticated encryption (encrypt-then-MAC): tampering or a wrong
 *    passphrase is detected and rejected, never silently mis-decrypted.
 *
 * Construction (all HMAC-SHA256 based, standard building blocks):
 *  - Key derivation: PBKDF2-HMAC-SHA256(passphrase, salt, iterations) -> 64 bytes,
 *    split into a 32-byte encryption key Ke and a 32-byte MAC key Km.
 *  - Cipher: HMAC-SHA256 counter-mode keystream under Ke XORed over the
 *    plaintext (a PRF stream cipher). A fresh random 16-byte nonce per backup.
 *  - Integrity: tag = HMAC-SHA256(Km, header-fields || nonce || ciphertext).
 *
 * The blob is versioned JSON so the format can evolve. Secrets are only ever in
 * memory during export/import; at rest they stay in the OS keystore (store.ts).
 */
import * as Crypto from 'expo-crypto';

import { hmac, sha256 } from './crypto';
import { listAccounts, addAccount } from './store';
import type { OtpAccount } from './otp';

const MAGIC = 'oidx-authenticator-backup';
const VERSION = 1;
const PBKDF2_ITERATIONS = 150_000;

type HashFn = (bytes: number[]) => number[];
const H: HashFn = sha256;

function hmac256(key: number[], msg: number[]): number[] {
  return hmac(H, key, msg);
}

function randomBytes(n: number): number[] {
  return Array.from(Crypto.getRandomBytes(n));
}

function utf8(s: string): number[] {
  // TextEncoder is available in RN's JS engine (Hermes) and on web.
  return Array.from(new TextEncoder().encode(s));
}

function bytesToB64(bytes: number[]): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  // btoa exists in RN/Hermes and web; guard just in case.
  if (typeof btoa === 'function') return btoa(bin);
  return (globalThis as any).Buffer.from(bin, 'binary').toString('base64');
}

function b64ToBytes(b64: string): number[] {
  const bin =
    typeof atob === 'function'
      ? atob(b64)
      : (globalThis as any).Buffer.from(b64, 'base64').toString('binary');
  const out: number[] = [];
  for (let i = 0; i < bin.length; i++) out.push(bin.charCodeAt(i) & 0xff);
  return out;
}

function xor(a: number[], b: number[]): number[] {
  const out = new Array<number>(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function u32be(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

/** PBKDF2-HMAC-SHA256 (RFC 8018) producing `dkLen` bytes. */
function pbkdf2(password: number[], salt: number[], iterations: number, dkLen: number): number[] {
  const hLen = 32;
  const blocks = Math.ceil(dkLen / hLen);
  const dk: number[] = [];
  for (let i = 1; i <= blocks; i++) {
    // U1 = HMAC(password, salt || INT_32_BE(i))
    let u = hmac256(password, salt.concat(u32be(i)));
    const t = u.slice();
    for (let c = 1; c < iterations; c++) {
      u = hmac256(password, u);
      for (let j = 0; j < hLen; j++) t[j] ^= u[j];
    }
    dk.push(...t);
  }
  return dk.slice(0, dkLen);
}

/** HMAC-SHA256 counter-mode keystream of `length` bytes under key Ke + nonce. */
function keystream(ke: number[], nonce: number[], length: number): number[] {
  const out: number[] = [];
  let counter = 0;
  while (out.length < length) {
    const block = hmac256(ke, nonce.concat(u32be(counter)));
    out.push(...block);
    counter++;
  }
  return out.slice(0, length);
}

/** The exportable subset of an account (drop id/createdAt — regenerated on import). */
type BackupAccount = Omit<OtpAccount, 'id' | 'createdAt'>;

export type AuthenticatorBackup = {
  magic: string;
  version: number;
  kdf: 'pbkdf2-hmac-sha256';
  iterations: number;
  salt: string; // base64
  nonce: string; // base64
  ciphertext: string; // base64
  tag: string; // base64
};

/**
 * Encrypt all stored authenticator accounts into a passphrase-protected blob
 * (a JSON string the caller can share/save as a file).
 */
export async function exportBackup(passphrase: string): Promise<string> {
  if (passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters.');
  }
  const accounts = await listAccounts();
  const payload: BackupAccount[] = accounts.map(({ id: _id, createdAt: _c, ...rest }) => rest);
  const plaintext = utf8(JSON.stringify(payload));

  const salt = randomBytes(16);
  const nonce = randomBytes(16);
  const dk = pbkdf2(utf8(passphrase), salt, PBKDF2_ITERATIONS, 64);
  const ke = dk.slice(0, 32);
  const km = dk.slice(32, 64);

  const ciphertext = xor(plaintext, keystream(ke, nonce, plaintext.length));

  const header = utf8(`${MAGIC}:${VERSION}:${PBKDF2_ITERATIONS}`);
  const tag = hmac256(km, header.concat(salt).concat(nonce).concat(ciphertext));

  const backup: AuthenticatorBackup = {
    magic: MAGIC,
    version: VERSION,
    kdf: 'pbkdf2-hmac-sha256',
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToB64(salt),
    nonce: bytesToB64(nonce),
    ciphertext: bytesToB64(ciphertext),
    tag: bytesToB64(tag),
  };
  return JSON.stringify(backup);
}

/**
 * Decrypt a backup blob and merge its accounts into the local store. Verifies
 * the MAC first: a wrong passphrase or tampered blob throws before anything is
 * imported. Returns the number of accounts imported.
 */
export async function importBackup(blob: string, passphrase: string): Promise<number> {
  let backup: AuthenticatorBackup;
  try {
    backup = JSON.parse(blob) as AuthenticatorBackup;
  } catch {
    throw new Error('This file is not a valid backup.');
  }
  if (backup.magic !== MAGIC || backup.version !== VERSION) {
    throw new Error('Unsupported or unrecognized backup format.');
  }

  const salt = b64ToBytes(backup.salt);
  const nonce = b64ToBytes(backup.nonce);
  const ciphertext = b64ToBytes(backup.ciphertext);
  const tag = b64ToBytes(backup.tag);
  const iterations = backup.iterations || PBKDF2_ITERATIONS;

  const dk = pbkdf2(utf8(passphrase), salt, iterations, 64);
  const ke = dk.slice(0, 32);
  const km = dk.slice(32, 64);

  const header = utf8(`${MAGIC}:${backup.version}:${iterations}`);
  const expected = hmac256(km, header.concat(salt).concat(nonce).concat(ciphertext));
  if (!constantTimeEqual(expected, tag)) {
    throw new Error('Wrong passphrase or the backup has been modified.');
  }

  const plaintext = xor(ciphertext, keystream(ke, nonce, ciphertext.length));
  let json: BackupAccount[];
  try {
    json = JSON.parse(new TextDecoder().decode(new Uint8Array(plaintext))) as BackupAccount[];
  } catch {
    throw new Error('Backup could not be decoded.');
  }

  let imported = 0;
  for (const acct of json) {
    if (!acct || typeof acct.secret !== 'string') continue;
    await addAccount(acct);
    imported++;
  }
  return imported;
}

function constantTimeEqual(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
