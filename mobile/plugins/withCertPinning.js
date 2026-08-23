/**
 * Expo config plugin: TLS certificate (public-key) pinning for the OpenIDX
 * mobile app.
 *
 * WHY: the app talks to a single, known OpenIDX host over HTTPS. Pinning the
 * server's SPKI (public-key) hashes means a network attacker who obtains a
 * mis-issued but CA-valid certificate still can't MITM the app's API/OAuth
 * traffic — the OS rejects any chain whose keys don't match a pin.
 *
 * HOW: this generates an Android Network Security Config <pin-set> for the
 * configured host(s) and wires AndroidManifest to use it. iOS App Transport
 * Security has no declarative public-key pinning, so iOS pinning would need a
 * native library (e.g. TrustKit); this plugin covers Android now and documents
 * the iOS path (see HANDOFF/CLAUDE-DEV-GUIDE).
 *
 * SAFETY: pinning is OPT-IN. Config comes from app.json `extra.certPinning`:
 *
 *   "extra": {
 *     "certPinning": {
 *       "host": "openidx.tdv.org",
 *       "pins": ["sha256/<leafSPKI>", "sha256/<intermediateSPKI>"],
 *       "expiration": "2027-01-01"     // optional; after this Android ignores the pins
 *     }
 *   }
 *
 * If `extra.certPinning` (or its pins) is absent, the plugin is a no-op — a
 * fresh build keeps working and we never brick clients with a stale pin. Always
 * ship at least TWO pins (current leaf + intermediate, or a backup key) so a
 * certificate/key rotation doesn't lock every installed app out.
 */
const { withAndroidManifest, withDangerousMod, AndroidConfig } = require('@expo/config-plugins');
const fs = require('fs');
const path = require('path');

const NSC_FILE = 'network_security_config.xml';

function normalizePins(pins) {
  // Accept "sha256/AAA=" or bare "AAA="; emit the base64 digest the XML wants.
  return (pins || [])
    .filter((p) => typeof p === 'string' && p.trim() !== '')
    .map((p) => p.trim())
    .map((p) => (p.startsWith('sha256/') ? p.slice('sha256/'.length) : p));
}

function buildNetworkSecurityConfigXml({ host, pins, expiration }) {
  const digests = normalizePins(pins);
  const pinLines = digests
    .map((d) => `      <pin digest="SHA-256">${d}</pin>`)
    .join('\n');
  const expirationAttr = expiration ? ` expiration="${expiration}"` : '';
  // cleartextTrafficPermitted=false: belt-and-suspenders against accidental http.
  return `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">${host}</domain>
    <pin-set${expirationAttr}>
${pinLines}
    </pin-set>
  </domain-config>
</network-security-config>
`;
}

function withCertPinning(config) {
  const pinning = config.extra?.certPinning;
  const pins = normalizePins(pinning?.pins);
  if (!pinning || !pinning.host || pins.length === 0) {
    // Opt-in: no config → no-op (never ship an empty/placeholder pin-set).
    return config;
  }

  // 1. Write res/xml/network_security_config.xml during prebuild.
  config = withDangerousMod(config, [
    'android',
    async (cfg) => {
      const resXmlDir = path.join(
        cfg.modRequest.platformProjectRoot,
        'app',
        'src',
        'main',
        'res',
        'xml',
      );
      fs.mkdirSync(resXmlDir, { recursive: true });
      fs.writeFileSync(
        path.join(resXmlDir, NSC_FILE),
        buildNetworkSecurityConfigXml({
          host: pinning.host,
          pins,
          expiration: pinning.expiration,
        }),
        'utf8',
      );
      return cfg;
    },
  ]);

  // 2. Point the <application> at the config.
  config = withAndroidManifest(config, (cfg) => {
    const app = AndroidConfig.Manifest.getMainApplicationOrThrow(cfg.modResults);
    app.$['android:networkSecurityConfig'] = '@xml/network_security_config';
    return cfg;
  });

  return config;
}

module.exports = withCertPinning;
// Exported for the plugin self-test (scripts/certpin-selftest.mjs).
module.exports.buildNetworkSecurityConfigXml = buildNetworkSecurityConfigXml;
module.exports.normalizePins = normalizePins;
