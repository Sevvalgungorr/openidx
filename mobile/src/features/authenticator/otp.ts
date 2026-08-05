/**
 * RFC 6238 TOTP / RFC 4226 HOTP code generation and otpauth:// URI parsing —
 * the engine that makes this app behave like Google Authenticator / Microsoft
 * Authenticator. Everything here is offline and deterministic: given a secret
 * and the current time, it produces the same rotating code the service expects.
 */
import { base32Decode, hmac, sha1, sha256, isValidBase32 } from './crypto';

export type OtpAlgorithm = 'SHA1' | 'SHA256';
export type OtpType = 'totp' | 'hotp';

/** A stored authenticator account (one row in the codes list). */
export interface OtpAccount {
  id: string;
  issuer: string; // "Google", "GitHub", ...
  label: string; // account name / email
  secret: string; // base32, as provided by the service
  algorithm: OtpAlgorithm;
  digits: number; // usually 6
  period: number; // seconds, usually 30 (totp)
  type: OtpType;
  counter?: number; // hotp only
  createdAt: number;
}

function hashFor(algorithm: OtpAlgorithm) {
  return algorithm === 'SHA256' ? sha256 : sha1;
}

/** RFC 4226 HOTP: derive one code from a secret and a counter. */
export function generateHOTP(
  secretBase32: string,
  counter: number,
  digits: number,
  algorithm: OtpAlgorithm
): string {
  const key = base32Decode(secretBase32);

  // 8-byte big-endian counter.
  const counterBytes: number[] = new Array(8).fill(0);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = c & 0xff;
    c = Math.floor(c / 256);
  }

  const hs = hmac(hashFor(algorithm), key, counterBytes);
  const offset = hs[hs.length - 1] & 0x0f;
  const binary =
    ((hs[offset] & 0x7f) << 24) |
    ((hs[offset + 1] & 0xff) << 16) |
    ((hs[offset + 2] & 0xff) << 8) |
    (hs[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return String(otp).padStart(digits, '0');
}

/** RFC 6238 TOTP: the time-based code for `nowMs` (defaults to real time). */
export function generateTOTP(account: OtpAccount, nowMs: number = Date.now()): string {
  const counter = Math.floor(nowMs / 1000 / account.period);
  return generateHOTP(account.secret, counter, account.digits, account.algorithm);
}

/** Seconds remaining in the current TOTP window (for the countdown ring). */
export function secondsRemaining(period: number, nowMs: number = Date.now()): number {
  const seconds = Math.floor(nowMs / 1000);
  return period - (seconds % period);
}

/** Group a code into two halves ("123 456") the way authenticator apps do. */
export function formatCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

/**
 * Parse an otpauth:// URI — the exact payload encoded in the QR codes services
 * present during 2FA setup. Returns the fields needed to build an OtpAccount,
 * or null when the URI is malformed / uses an unsupported algorithm.
 *
 * Example:
 *   otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30&algorithm=SHA1
 */
export function parseOtpauthUri(uri: string): Omit<OtpAccount, 'id' | 'createdAt'> | null {
  const trimmed = uri.trim();
  const match = /^otpauth:\/\/(totp|hotp)\/([^?]*)\?(.*)$/i.exec(trimmed);
  if (!match) return null;

  const type = match[1].toLowerCase() as OtpType;
  const rawLabel = decodeURIComponent(match[2] || '');
  const query = match[3];

  const params: Record<string, string> = {};
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    const k = decodeURIComponent(pair.slice(0, eq)).toLowerCase();
    const v = decodeURIComponent(pair.slice(eq + 1));
    params[k] = v;
  }

  const secret = (params.secret || '').replace(/\s/g, '');
  if (!isValidBase32(secret)) return null;

  // Label is "Issuer:account" or just "account"; the issuer= param wins.
  let issuer = params.issuer || '';
  let accountLabel = rawLabel;
  const colon = rawLabel.indexOf(':');
  if (colon >= 0) {
    if (!issuer) issuer = rawLabel.slice(0, colon).trim();
    accountLabel = rawLabel.slice(colon + 1).trim();
  }

  const algoRaw = (params.algorithm || 'SHA1').toUpperCase();
  if (algoRaw !== 'SHA1' && algoRaw !== 'SHA256') {
    // SHA512 and exotic algorithms aren't supported by the pure-JS core.
    return null;
  }

  const digits = clampInt(parseInt(params.digits || '6', 10), 6, 8, 6);
  const period = clampInt(parseInt(params.period || '30', 10), 10, 120, 30);
  const counter = type === 'hotp' ? clampInt(parseInt(params.counter || '0', 10), 0, 1e15, 0) : undefined;

  return {
    issuer: issuer || 'Account',
    label: accountLabel || issuer || 'Account',
    secret,
    algorithm: algoRaw as OtpAlgorithm,
    digits,
    period,
    type,
    counter,
  };
}

function clampInt(n: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

/**
 * Build the canonical otpauth:// URI for an account — the exact string a QR code
 * encodes. This is what lets OpenIDX *produce* a code (to move an account to
 * another authenticator, or to show the QR a freshly-generated secret should be
 * scanned into), mirroring how services present 2FA setup.
 *
 *   otpauth://totp/Issuer:label?secret=...&issuer=Issuer&algorithm=SHA1&digits=6&period=30
 */
export function buildOtpauthUri(
  account: Pick<
    OtpAccount,
    'issuer' | 'label' | 'secret' | 'algorithm' | 'digits' | 'period' | 'type' | 'counter'
  >
): string {
  const issuer = account.issuer?.trim() || 'OpenIDX';
  const label = account.label?.trim() || issuer;
  // Label is conventionally "Issuer:account"; both parts are percent-encoded.
  const path = `${encodeURIComponent(issuer)}:${encodeURIComponent(label)}`;

  const params: string[] = [
    `secret=${encodeURIComponent(account.secret)}`,
    `issuer=${encodeURIComponent(issuer)}`,
    `algorithm=${account.algorithm}`,
    `digits=${account.digits}`,
  ];
  if (account.type === 'hotp') {
    params.push(`counter=${account.counter ?? 0}`);
  } else {
    params.push(`period=${account.period}`);
  }
  return `otpauth://${account.type}/${path}?${params.join('&')}`;
}

/**
 * Generate a fresh, cryptographically-random base32 TOTP secret so OpenIDX can
 * mint an account itself (and then show its QR / setup key), instead of only
 * importing one from another service. `bytes` of entropy → RFC 4648 base32.
 * 20 bytes (160 bits) matches what Google/Microsoft issue.
 */
export function generateSecret(randomBytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < randomBytes.length; i++) {
    value = (value << 8) | randomBytes[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 31];
  }
  return out;
}
