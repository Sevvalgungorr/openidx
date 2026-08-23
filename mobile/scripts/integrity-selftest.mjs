#!/usr/bin/env node
/**
 * Pure-logic checks for the device-integrity warning mapping
 * (features/security/integrity.ts). The native detection can't run under Node,
 * but integrityWarning() is a pure mapping we can lock in. Run with:
 *   node scripts/integrity-selftest.mjs
 */

// Mirror of integrityWarning() — kept in sync with the source.
function integrityWarning(s) {
  if (s.compromised) {
    return 'This device appears to be rooted or jailbroken. Your codes and sign-in are less secure here; avoid using it for sensitive accounts.';
  }
  if (s.emulator) {
    return 'Running on an emulator/simulator. Keystore protection is weaker than on a real device.';
  }
  return null;
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

check('clean device → no warning', integrityWarning({ compromised: false, emulator: false, rooted: false }) === null);
check('unknown root → no warning', integrityWarning({ compromised: false, emulator: false, rooted: null }) === null);
check('rooted → warns about root', /rooted or jailbroken/.test(integrityWarning({ compromised: true, emulator: false, rooted: true }) || ''));
check('emulator only → emulator note', /emulator\/simulator/.test(integrityWarning({ compromised: false, emulator: true, rooted: false }) || ''));
check('compromised takes precedence over emulator', /rooted or jailbroken/.test(integrityWarning({ compromised: true, emulator: true, rooted: true }) || ''));

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nAll integrity self-tests passed.');
