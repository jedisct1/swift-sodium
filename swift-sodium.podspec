Pod::Spec.new do |s|
s.name = 'swift-sodium'
s.version = '0.1'
s.license = 'Frank Denis'
s.summary = 'Swift-Sodium provides a safe and easy to use interface to perform common cryptographic operations on iOS and OSX.'
s.homepage = 'https://github.com/jedisct1/swift-sodium'
s.social_media_url = 'http://twitter.com/jedisct1'
s.authors = { 'Frank Denis' => '' }
s.source = { :git => 'https://github.com/jedisct1/swift-sodium.git' }
# s.source = { :git => 'https://github.com/jedisct1/swift-sodium.git', :tag => s.version }

s.ios.deployment_target = '8.1'
s.osx.deployment_target = '10.10'

s.source_files = 'Sodium/*.{swift,h,a}'

s.requires_arc = true
end