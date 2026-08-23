#!/usr/bin/env node
/**
 * Self-test for the cert-pinning config plugin's pure logic
 * (plugins/withCertPinning.js). It does not run a full prebuild — it asserts the
 * generated Network Security Config XML is correct for the pins we ship. Run:
 *   node scripts/certpin-selftest.mjs
 */
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const plugin = require('../plugins/withCertPinning.js');
const { buildNetworkSecurityConfigXml, normalizePins } = plugin;

let failures = 0;
function check(name, cond) {
  if (!cond) {
    console.error('FAIL:', name);
    failures++;
  } else {
    console.log('ok  :', name);
  }
}

// normalizePins strips the sha256/ prefix and trims.
const norm = normalizePins(['sha256/AAA=', '  BBB=  ', '', null]);
check('normalizePins strips prefix + trims + drops empties',
  norm.length === 2 && norm[0] === 'AAA=' && norm[1] === 'BBB=');

// The XML carries every pin as a SHA-256 pin, the domain with subdomains, an
// expiration, and forbids cleartext.
const xml = buildNetworkSecurityConfigXml({
  host: 'openidx.tdv.org',
  pins: ['sha256/pcThjmVDuiW/+iCA4QbfaMz0t+We+JcD98PAaL1d744=', 'cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A='],
  expiration: '2027-01-01',
});
check('has domain with includeSubdomains', /<domain includeSubdomains="true">openidx\.tdv\.org<\/domain>/.test(xml));
check('has both pins as SHA-256', (xml.match(/<pin digest="SHA-256">/g) || []).length === 2);
check('leaf pin present', xml.includes('pcThjmVDuiW/+iCA4QbfaMz0t+We+JcD98PAaL1d744='));
check('intermediate pin present', xml.includes('cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A='));
check('sha256/ prefix stripped in XML', !xml.includes('sha256/'));
check('expiration set', xml.includes('expiration="2027-01-01"'));
check('cleartext forbidden', xml.includes('cleartextTrafficPermitted="false"'));

// A backup pin is mandatory operationally: assert we ship at least two.
check('ships >= 2 pins (rotation safety)', (xml.match(/<pin /g) || []).length >= 2);

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nAll cert-pinning self-tests passed.');
