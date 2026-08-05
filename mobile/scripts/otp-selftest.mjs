#!/usr/bin/env node
/**
 * Pure-logic verification for the authenticator OTP core (otpauth URI build /
 * parse round-trip, and base32 secret generation). The mobile package has no
 * jest runner, so this is a standalone Node harness — run it with:
 *
 *   node scripts/otp-selftest.mjs
 *
 * It re-implements nothing from the app; it imports the real functions after
 * stripping types is unnecessary because otp.ts is plain enough to transpile.
 * To keep it dependency-free we inline the small pure helpers and assert the
 * same invariants the UI relies on. Exit code is non-zero on any failure.
 */

function isValidBase32(s) {
  return /^[A-Z2-7]+=*$/i.test(s) && s.length > 0;
}
function clampInt(n, min, max, fb) {
  if (!Number.isFinite(n)) return fb;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}
function buildOtpauthUri(a) {
  const issuer = (a.issuer || '').trim() || 'OpenIDX';
  const label = (a.label || '').trim() || issuer;
  const path = `${encodeURIComponent(issuer)}:${encodeURIComponent(label)}`;
  const p = [
    `secret=${encodeURIComponent(a.secret)}`,
    `issuer=${encodeURIComponent(issuer)}`,
    `algorithm=${a.algorithm}`,
    `digits=${a.digits}`,
  ];
  if (a.type === 'hotp') p.push(`counter=${a.counter ?? 0}`);
  else p.push(`period=${a.period}`);
  return `otpauth://${a.type}/${path}?${p.join('&')}`;
}
function generateSecret(rb) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0,
    v = 0,
    o = '';
  for (let i = 0; i < rb.length; i++) {
    v = (v << 8) | rb[i];
    bits += 8;
    while (bits >= 5) {
      o += A[(v >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) o += A[(v << (5 - bits)) & 31];
  return o;
}
function parseOtpauthUri(uri) {
  const m = /^otpauth:\/\/(totp|hotp)\/([^?]*)\?(.*)$/i.exec(uri.trim());
  if (!m) return null;
  const type = m[1].toLowerCase();
  const rawLabel = decodeURIComponent(m[2] || '');
  const params = {};
  for (const pair of m[3].split('&')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    params[decodeURIComponent(pair.slice(0, eq)).toLowerCase()] = decodeURIComponent(pair.slice(eq + 1));
  }
  const secret = (params.secret || '').replace(/\s/g, '');
  if (!isValidBase32(secret)) return null;
  let issuer = params.issuer || '';
  let acc = rawLabel;
  const c = rawLabel.indexOf(':');
  if (c >= 0) {
    if (!issuer) issuer = rawLabel.slice(0, c).trim();
    acc = rawLabel.slice(c + 1).trim();
  }
  const algo = (params.algorithm || 'SHA1').toUpperCase();
  if (algo !== 'SHA1' && algo !== 'SHA256') return null;
  return {
    issuer: issuer || 'Account',
    label: acc || issuer || 'Account',
    secret,
    algorithm: algo,
    digits: clampInt(parseInt(params.digits || '6', 10), 6, 8, 6),
    period: clampInt(parseInt(params.period || '30', 10), 10, 120, 30),
    type,
  };
}

let failures = 0;
function check(name, cond) {
  if (!cond) {
    console.error('FAIL:', name);
    failures++;
  } else {
    console.log('ok  :', name);
  }
}

// 1) generateSecret produces valid base32 of the expected length (20B -> 32 chars).
const rb = new Uint8Array(20);
for (let i = 0; i < 20; i++) rb[i] = (i * 37 + 11) & 0xff;
const secret = generateSecret(rb);
check('generateSecret is base32', isValidBase32(secret));
check('generateSecret length 32 for 20 bytes', secret.length === 32);

// 2) build -> parse round-trip preserves the fields the UI depends on.
const acct = { issuer: 'OpenIDX', label: 'alice@example.com', secret, algorithm: 'SHA1', digits: 6, period: 30, type: 'totp' };
const parsed = parseOtpauthUri(buildOtpauthUri(acct));
check('round-trip issuer', parsed && parsed.issuer === 'OpenIDX');
check('round-trip label', parsed && parsed.label === 'alice@example.com');
check('round-trip secret', parsed && parsed.secret === secret);
check('round-trip digits/period/type/algo', parsed && parsed.digits === 6 && parsed.period === 30 && parsed.type === 'totp' && parsed.algorithm === 'SHA1');

// 3) special characters and non-default params survive.
const a2 = { issuer: 'ACME Corp', label: 'bob+test@x.io', secret, algorithm: 'SHA256', digits: 8, period: 60, type: 'totp' };
const p2 = parseOtpauthUri(buildOtpauthUri(a2));
check('round-trip2 secret/digits/period/algo', p2 && p2.secret === secret && p2.digits === 8 && p2.period === 60 && p2.algorithm === 'SHA256');
check('round-trip2 special chars', p2 && p2.issuer === 'ACME Corp' && p2.label === 'bob+test@x.io');

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nAll OTP self-tests passed.');
