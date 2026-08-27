/**
 * Expo config plugin: TLS certificate (public-key) pinning for iOS.
 *
 * WHY: the Android half of this (plugins/withCertPinning.js) writes a Network
 * Security Config and the *operating system* enforces it — no app code runs.
 * iOS has no declarative equivalent: App Transport Security cannot pin public
 * keys. So iOS needs a library, and that library has to be present, configured
 * and actually running. This plugin does all three, from the same
 * `extra.certPinning` block the Android plugin reads, so the two platforms
 * cannot drift apart.
 *
 * WHAT IT PRODUCES, per prebuild:
 *   1. Podfile     — `pod 'TrustKit', '3.0.7', :modular_headers => true`
 *   2. Info.plist  — a TSKConfiguration policy for the configured host
 *   3. AppDelegate — an explicit TrustKit.initSharedInstance(...) call
 *
 * ABOUT (3): TrustKit already self-initializes from Info.plist through a
 * library constructor (`__attribute__((constructor))` in TrustKit.m). That
 * constructor only runs if the linker actually pulls in the object file that
 * contains it, which for a static library depends on link flags rather than on
 * anything this project controls. The explicit call removes that dependency.
 * It is safe to have both: initSharedInstanceWithConfiguration: is wrapped in
 * dispatch_once, so whichever runs first wins and the second is a no-op.
 *
 * ABOUT modular_headers: TrustKit is Objective-C. Swift can only `import
 * TrustKit` if CocoaPods generates a module map for it, which a React Native
 * project — built with static libraries, not frameworks — does not do by
 * default.
 *
 * SAFETY: opt-in, exactly like the Android plugin. No `extra.certPinning`, no
 * host, or fewer than two pins → this is a no-op. Two pins is not a style
 * preference: with a single pin, one key rotation locks every installed app
 * out of the API with no way to recover but an App Store update.
 */
const { withInfoPlist, withPodfile, withAppDelegate } = require('@expo/config-plugins');

/**
 * The TrustKit release this plugin is written against and tested with.
 *
 * Pinned rather than floating on purpose. This is a security control: a
 * dependency that can change under us can change what "pinned" means, and an
 * unbounded `pod 'TrustKit'` would let a future major silently alter the
 * defaults that decide whether a connection is refused. The Android side has
 * no such exposure — its pinning is a platform feature with no third-party
 * code — so this is surface iOS adds and iOS has to hold down.
 */
const TRUSTKIT_VERSION = '3.0.7';

function normalizePins(pins) {
  // Accept "sha256/AAA=" or bare "AAA="; TrustKit's TSKPublicKeyHashes wants
  // the bare base64, same as Android's <pin digest="SHA-256">.
  return (pins || [])
    .filter((pin) => typeof pin === 'string' && pin.trim() !== '')
    .map((pin) => pin.trim())
    .map((pin) => (pin.startsWith('sha256/') ? pin.slice('sha256/'.length) : pin));
}

/**
 * The pinning policy, as TrustKit reads it from Info.plist.
 *
 * Deliberately equivalent to what the Android plugin emits, key for key:
 * same host, same subdomain rule, same pins, same expiry — and enforcing,
 * because Android's <pin-set> enforces. A policy that only reports would be
 * the worst of both worlds: the cost of pinning with none of the protection,
 * and a codebase that says "iOS is pinned" when nothing is refused.
 */
function buildTrustKitConfig({ host, pins, expiration }) {
  const hashes = normalizePins(pins);

  return {
    // Hook NSURLSession/NSURLConnection so the app's existing networking is
    // covered without every call site opting in. TrustKit's own docs are wary
    // of swizzling, and whether it covers React Native's HTTP layer is a
    // question only a device can answer — see the plugin's README note.
    TSKSwizzleNetworkDelegates: true,
    TSKPinnedDomains: {
      [host]: {
        TSKIncludeSubdomains: true,
        // Refuse the connection on mismatch. This is the line that makes the
        // difference between pinning and pretending.
        TSKEnforcePinning: true,
        TSKPublicKeyHashes: hashes,
        // After this date TrustKit stops enforcing, the same way Android
        // ignores an expired <pin-set>. Both fail OPEN, which is the right
        // default for a pin nobody rotated — and a calendar entry.
        ...(expiration ? { TSKExpirationDate: expiration } : {}),
      },
    },
  };
}

/** The exact Podfile line, so the self-test can assert the version is pinned. */
function podLine() {
  return `  pod 'TrustKit', '${TRUSTKIT_VERSION}', :modular_headers => true`;
}

/**
 * The Swift that guarantees TrustKit is running, whatever the linker did with
 * the library constructor. Reads the very policy this plugin just wrote.
 */
function appDelegateInit() {
  return [
    '    // Certificate pinning. The policy lives in Info.plist (TSKConfiguration),',
    '    // written by plugins/withCertPinningIOS.js. TrustKit also self-initializes',
    '    // from there via a library constructor; this call makes it deterministic',
    '    // rather than dependent on link flags. Double init is a no-op.',
    '    if let pinningPolicy = Bundle.main.object(forInfoDictionaryKey: "TSKConfiguration") as? [String: Any] {',
    '      TrustKit.initSharedInstance(withConfiguration: pinningPolicy)',
    '    }',
  ].join('\n');
}

/**
 * Put the import and the init call into the generated Swift AppDelegate.
 *
 * Done by hand rather than with mergeContents(): that helper matches its anchor
 * one line at a time, and the thing we need to find — the opening brace of
 * `application(_:didFinishLaunchingWithOptions:)` — is three lines below the
 * name it belongs to. Anchoring on a bare `-> Bool {` would have worked by
 * accident: this file has three of them, and only the first is the right one.
 *
 * So: find the parameter, then the brace that closes its signature. Anything
 * unexpected throws, because the failure mode of guessing here is an app that
 * looks pinned and never initializes.
 */
function insertTrustKitInit(contents) {
  // Idempotent: a second prebuild over an existing ios/ must not stack copies.
  if (contents.includes('TrustKit.initSharedInstance')) {
    return contents;
  }

  const lines = contents.split('\n');
  const importIndex = lines.findIndex((line) => line.trim() === 'import React');

  if (importIndex === -1) {
    throw new Error('withCertPinningIOS: no `import React` in AppDelegate.swift.');
  }

  const paramIndex = lines.findIndex((line) =>
    line.includes('didFinishLaunchingWithOptions launchOptions'),
  );

  if (paramIndex === -1) {
    throw new Error(
      'withCertPinningIOS: no didFinishLaunchingWithOptions in AppDelegate.swift.',
    );
  }

  // The signature can span several lines; its body starts at the first line
  // after the parameter that ends the signature with `) -> Bool {`.
  const braceIndex = lines.findIndex(
    (line, i) => i >= paramIndex && /\)\s*->\s*Bool\s*\{\s*$/.test(line),
  );

  if (braceIndex === -1) {
    throw new Error(
      'withCertPinningIOS: could not find the body of didFinishLaunchingWithOptions.',
    );
  }

  // Bottom-up, so the first splice does not shift the second index.
  lines.splice(braceIndex + 1, 0, appDelegateInit());
  lines.splice(importIndex + 1, 0, 'import TrustKit');

  return lines.join('\n');
}

function withCertPinningIOS(config) {
  const pinning = config.extra?.certPinning;
  const pins = normalizePins(pinning?.pins);

  // Opt-in, exactly like the Android plugin: no config → no-op, so a fresh
  // build keeps working and a stale pin never bricks anyone.
  if (!pinning || !pinning.host || pins.length < 2) {
    return config;
  }

  config = withInfoPlist(config, (cfg) => {
    cfg.modResults.TSKConfiguration = buildTrustKitConfig({
      host: pinning.host,
      pins,
      expiration: pinning.expiration,
    });
    return cfg;
  });

  config = withPodfile(config, (cfg) => {
    if (cfg.modResults.contents.includes("pod 'TrustKit'")) {
      return cfg;
    }

    const targetRegex = /(target ['"][^'"]+['"] do)/;

    if (!targetRegex.test(cfg.modResults.contents)) {
      throw new Error('OpenIDX iOS target could not be found in Podfile.');
    }

    cfg.modResults.contents = cfg.modResults.contents.replace(
      targetRegex,
      `$1\n${podLine()}`,
    );

    return cfg;
  });

  config = withAppDelegate(config, (cfg) => {
    if (cfg.modResults.language !== 'swift') {
      // Every Expo SDK this project targets generates a Swift AppDelegate.
      // Refusing loudly beats writing Swift into an Objective-C++ file and
      // finding out at compile time, on a machine nobody has yet.
      throw new Error(
        `withCertPinningIOS: expected a Swift AppDelegate, got ${cfg.modResults.language}.`,
      );
    }

    cfg.modResults.contents = insertTrustKitInit(cfg.modResults.contents);
    return cfg;
  });

  return config;
}

module.exports = withCertPinningIOS;
// Exported for the plugin self-test (scripts/certpin-ios-selftest.mjs).
module.exports.normalizePins = normalizePins;
module.exports.buildTrustKitConfig = buildTrustKitConfig;
module.exports.podLine = podLine;
module.exports.appDelegateInit = appDelegateInit;
module.exports.insertTrustKitInit = insertTrustKitInit;
module.exports.TRUSTKIT_VERSION = TRUSTKIT_VERSION;
