Pod::Spec.new do |s|
s.name = 'Sodium'
s.version = '0.1'
s.license = { :type => "ISC", :file => 'LICENSE' }
s.summary = 'Swift-Sodium provides a safe and easy to use interface to perform common cryptographic operations on iOS and OSX.'
s.homepage = 'https://github.com/jedisct1/swift-sodium'
s.social_media_url = 'http://twitter.com/jedisct1'
s.authors = { 'Frank Denis' => '' }
s.source = { :git => 'https://github.com/jedisct1/swift-sodium.git' }

s.ios.deployment_target = '8.0'
s.osx.deployment_target = '10.9'

s.ios.vendored_library    = 'Sodium/libsodium-ios.a'
s.osx.vendored_library    = 'Sodium/libsodium-osx.a'

s.source_files = 'Sodium/*.{swift,h}'

s.requires_arc = true
end
