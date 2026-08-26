const {
  withInfoPlist,
  withPodfile,
} = require('@expo/config-plugins');

function normalizePins(pins) {
  return (pins || [])
    .filter((pin) => typeof pin === 'string' && pin.trim() !== '')
    .map((pin) => pin.trim())
    .map((pin) =>
      pin.startsWith('sha256/')
        ? pin.slice('sha256/'.length)
        : pin,
    );
}

function withCertPinningIOS(config) {
  const pinning = config.extra?.certPinning;
  const pins = normalizePins(pinning?.pins);

  // Android pluginindeki gibi config yoksa hiçbir şey yapma.
  if (!pinning || !pinning.host || pins.length < 2) {
    return config;
  }

  // iOS Info.plist içerisine TrustKit policy ekle.
  config = withInfoPlist(config, (cfg) => {
    cfg.modResults.TSKConfiguration = {
      TSKSwizzleNetworkDelegates: true,
      TSKPinnedDomains: {
        [pinning.host]: {
          TSKIncludeSubdomains: true,

          // İlk iOS testlerinde bağlantıyı kilitlememek için false.
          // Gerçek cihaz doğrulamasından sonra true yapılabilir.
          TSKEnforcePinning: false,

          TSKPublicKeyHashes: pins,
          ...(pinning.expiration
            ? { TSKExpirationDate: pinning.expiration }
            : {}),
        },
      },
    };

    return cfg;
  });

  // iOS native projeye TrustKit CocoaPod dependency ekle.
  config = withPodfile(config, (cfg) => {
    if (cfg.modResults.contents.includes("pod 'TrustKit'")) {
      return cfg;
    }

    const targetRegex = /(target ['"][^'"]+['"] do)/;

    if (!targetRegex.test(cfg.modResults.contents)) {
      throw new Error(
        'OpenIDX iOS target could not be found in Podfile.',
      );
    }

    cfg.modResults.contents =
      cfg.modResults.contents.replace(
        targetRegex,
        `$1\n  pod 'TrustKit'`,
      );

    return cfg;
  });

  return config;
}

module.exports = withCertPinningIOS;
module.exports.normalizePins = normalizePins;