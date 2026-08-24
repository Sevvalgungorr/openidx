#
# CocoaPods spec for the OpenIDX engine plugin.
#
# The Go engine ships as `Engine.xcframework`, produced by:
#   gomobile bind -target=ios -o Engine.xcframework ./agent/mobile
# Drop it at ios/Frameworks/Engine.xcframework (see README.md). CI's
# client-mobile-build.yml builds the xcframework, copies it into place, then
# runs `flutter build ios --no-codesign`.
#
Pod::Spec.new do |s|
  s.name             = 'openidx_engine'
  s.version          = '0.1.0'
  s.summary          = 'OpenIDX Go engine gomobile bridge for Flutter (iOS).'
  s.description      = 'Bridges Dart to the OpenIDX engine (agent/mobile) via Engine.xcframework.'
  s.homepage         = 'https://github.com/openidx/openidx'
  s.license          = { :type => 'Apache-2.0' }
  s.author           = { 'OpenIDX' => 'engineering@openidx.example' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'
  s.swift_version = '5.0'

  # Link the gomobile-produced xcframework. It must exist at build time; CI
  # stages it before `pod install`.
  s.vendored_frameworks = 'Frameworks/Engine.xcframework'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
