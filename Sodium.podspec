# Requires CocoaPods 1.10.0

Pod::Spec.new do |s|
s.name = 'Sodium'
s.version = '0.9.0'
s.swift_version = '5.0'
s.license = { :type => "ISC", :file => 'LICENSE' }
s.summary = 'Swift-Sodium provides a safe and easy to use interface to perform common cryptographic operations on iOS and OSX.'
s.homepage = 'https://github.com/jedisct1/swift-sodium'
s.social_media_url = 'https://twitter.com/jedisct1'
s.authors = { 'Frank Denis' => '' }
s.source = { :git => 'https://github.com/jedisct1/swift-sodium.git',
             :tag => '0.9.0' }

s.ios.deployment_target = '9.0'
s.osx.deployment_target = '10.11'
s.watchos.deployment_target = '5.0'

s.source_files = 'Sodium/**/*.{swift,h}'
s.private_header_files = 'Sodium/libsodium/*.h'

# Xcode 12 changed the way apps are built because of the upcoming support for
# Apple Silicon. We need explicitly exclude the arm64 architecture.
# More info at
# https://stackoverflow.com/questions/63607158/xcode-12-building-for-ios-simulator-but-linking-in-object-file-built-for-ios
s.pod_target_xcconfig = {
  'SWIFT_INCLUDE_PATHS' => '$(inherited) "${PODS_XCFRAMEWORKS_BUILD_DIR}/Clibsodium"',
  'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64',
  'EXCLUDED_ARCHS[sdk=watchsimulator*]' => 'arm64',
}

# Notice that a CocoaPods contributor discourages the use of
# `user_target_xcconfig`, but in this case also agrees that there might not be
# a better approach.
# See
# https://github.com/CocoaPods/CocoaPods/issues/10065#issuecomment-701055569
s.user_target_xcconfig = {
  'SWIFT_INCLUDE_PATHS' => '$(inherited) "${PODS_XCFRAMEWORKS_BUILD_DIR}/Clibsodium"',
  'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64',
  'EXCLUDED_ARCHS[sdk=watchsimulator*]' => 'arm64',
}

s.requires_arc = true

s.vendored_frameworks = 'Clibsodium.xcframework'
end
