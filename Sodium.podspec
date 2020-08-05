Pod::Spec.new do |s|
s.name = 'Sodium'
s.version = '0.8.0'
s.swift_version = '5.0'
s.license = { :type => "ISC", :file => 'LICENSE' }
s.summary = 'Swift-Sodium provides a safe and easy to use interface to perform common cryptographic operations on iOS and OSX.'
s.homepage = 'https://github.com/jedisct1/swift-sodium'
s.social_media_url = 'https://twitter.com/jedisct1'
s.authors = { 'Frank Denis' => '' }
s.source = { :git => 'https://github.com/jedisct1/swift-sodium.git',
             :tag => '0.8.0' }

s.ios.deployment_target = '8.0'
s.osx.deployment_target = '10.11'
s.watchos.deployment_target = '5.0'

s.source_files = 'Sodium/**/*.{swift,h}'
s.private_header_files = 'Sodium/libsodium/*.h'

s.pod_target_xcconfig = {
	'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/Sodium/libsodium',
}

s.requires_arc = true
end
