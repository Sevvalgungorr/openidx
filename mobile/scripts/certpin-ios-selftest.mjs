#!/usr/bin/env node
/**
 * Self-test for the iOS cert-pinning config plugin's pure logic
 * (plugins/withCertPinningIOS.js). The sibling of certpin-selftest.mjs, which
 * covers the Android half.
 *
 * It does not run a prebuild — it asserts the pieces the plugin writes are
 * right for the pins we ship, and in particular that the two things which
 * decide whether pinning is real are true: enforcement is ON, and the
 * dependency is version-pinned. Both have already been wrong once. Run:
 *   node scripts/certpin-ios-selftest.mjs
 */
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const plugin = require('../plugins/withCertPinningIOS.js');
const {
  buildTrustKitConfig,
  normalizePins,
  podLine,
  appDelegateInit,
  insertTrustKitInit,
  TRUSTKIT_VERSION,
} = plugin;

const HOST = 'openidx.tdv.org';
const LEAF = 'pcThjmVDuiW/+iCA4QbfaMz0t+We+JcD98PAaL1d744=';
const BACKUP = 'cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A=';

let failures = 0;
function check(name, cond) {
  if (!cond) {
    console.error('FAIL:', name);
    failures++;
  } else {
    console.log('ok  :', name);
  }
}

// --- pins ------------------------------------------------------------------

const norm = normalizePins(['sha256/AAA=', '  BBB=  ', '', null]);
check(
  'normalizePins strips prefix + trims + drops empties',
  norm.length === 2 && norm[0] === 'AAA=' && norm[1] === 'BBB=',
);

// --- the policy TrustKit reads ---------------------------------------------

const policy = buildTrustKitConfig({
  host: HOST,
  pins: [`sha256/${LEAF}`, BACKUP],
  expiration: '2027-01-01',
});
const domain = policy.TSKPinnedDomains[HOST];

check('policy is keyed by the configured host', Boolean(domain));
check('subdomains included', domain.TSKIncludeSubdomains === true);

// The one that decides whether this is pinning or theatre. It shipped as
// false once; a reporting-only policy costs everything pinning costs and
// refuses nothing.
check('ENFORCEMENT IS ON', domain.TSKEnforcePinning === true);

check('ships exactly the two pins we configured', domain.TSKPublicKeyHashes.length === 2);
check('leaf pin present', domain.TSKPublicKeyHashes.includes(LEAF));
check('backup pin present', domain.TSKPublicKeyHashes.includes(BACKUP));
check(
  'sha256/ prefix stripped (TrustKit wants bare base64)',
  domain.TSKPublicKeyHashes.every((h) => !h.startsWith('sha256/')),
);
check('expiration carried through', domain.TSKExpirationDate === '2027-01-01');
check('network delegates swizzled (covers the existing HTTP layer)',
  policy.TSKSwizzleNetworkDelegates === true);

// A backup pin is mandatory operationally, same rule as Android: with one pin,
// a key rotation locks every installed app out until an App Store update.
check('ships >= 2 pins (rotation safety)', domain.TSKPublicKeyHashes.length >= 2);

// Optional expiry: absent in config → absent in policy, never invented.
const noExpiry = buildTrustKitConfig({ host: HOST, pins: [LEAF, BACKUP] });
check(
  'no expiration configured → key omitted',
  !('TSKExpirationDate' in noExpiry.TSKPinnedDomains[HOST]),
);

// --- the dependency --------------------------------------------------------

const pod = podLine();
check('Podfile line declares TrustKit', pod.includes("pod 'TrustKit'"));
check('VERSION IS PINNED, not floating', pod.includes(`'${TRUSTKIT_VERSION}'`));
check('version looks like a release', /^\d+\.\d+\.\d+$/.test(TRUSTKIT_VERSION));
check(
  'modular headers requested (Swift cannot import an ObjC pod without them)',
  pod.includes(':modular_headers => true'),
);

// --- the initialization ----------------------------------------------------

const init = appDelegateInit();
check('AppDelegate snippet initializes the shared instance',
  init.includes('TrustKit.initSharedInstance(withConfiguration:'));
check('…from the policy this plugin wrote into Info.plist',
  init.includes('forInfoDictionaryKey: "TSKConfiguration"'));

// --- writing it into the AppDelegate --------------------------------------
//
// The part that already went wrong once: an anchor that matched nothing, and a
// prebuild that failed outright. Better here than on a build machine.

// The Swift template Expo generates. Three `-> Bool {` lines, and only the
// first one belongs to the launch method.
const APP_DELEGATE = [
  'internal import Expo',
  'import React',
  'import ReactAppDependencyProvider',
  '',
  '@main',
  'class AppDelegate: ExpoAppDelegate {',
  '  public override func application(',
  '    _ application: UIApplication,',
  '    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil',
  '  ) -> Bool {',
  '    let delegate = ReactNativeDelegate()',
  '    return super.application(application, didFinishLaunchingWithOptions: launchOptions)',
  '  }',
  '',
  '  public override func application(',
  '    _ app: UIApplication,',
  '    open url: URL,',
  '    options: [UIApplication.OpenURLOptionsKey: Any] = [:]',
  '  ) -> Bool {',
  '    return false',
  '  }',
  '}',
].join('\n');

const patched = insertTrustKitInit(APP_DELEGATE);
const patchedLines = patched.split('\n');

check('import added', patchedLines.filter((l) => l === 'import TrustKit').length === 1);
check(
  'init added exactly once',
  (patched.match(/TrustKit\.initSharedInstance/g) || []).length === 1,
);

// The init must land in the launch method, not in the second `-> Bool {`.
const initLine = patchedLines.findIndex((l) => l.includes('TrustKit.initSharedInstance'));
const bodyLine = patchedLines.findIndex((l) => l.includes('let delegate = ReactNativeDelegate()'));
const openUrlLine = patchedLines.findIndex((l) => l.includes('open url: URL'));
check('init is inside didFinishLaunchingWithOptions', initLine < bodyLine);
check('init is NOT in the second -> Bool method', initLine < openUrlLine);

// Running prebuild twice must not stack copies.
const twice = insertTrustKitInit(patched);
check('idempotent', twice === patched);

// And it refuses rather than silently doing nothing when the template moves.
let threw = false;
try {
  insertTrustKitInit('import React\nclass AppDelegate {}');
} catch {
  threw = true;
}
check('throws when the launch method is missing (never a silent no-op)', threw);

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nAll iOS cert-pinning self-tests passed.');
