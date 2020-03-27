Pod::Spec.new do |spec|

  spec.name                  = "Envelope"
  spec.version               = "1.0.3"
  spec.summary               = "OpenSSL-compatible file encryption in Swift"

  spec.description           = "Envelope is a hybrid cryptosystem that encrypts files efficiently and securely, supporting most symmetric and public-key ciphers. Envelope uses `AES256-CBC` and `RSA-2048` by default, and supports externally created (ie. OpenSSL) public-keys."

  spec.homepage              = "https://github.com/george-lim/envelope"
  spec.license               = { :type => "MIT", :file => "LICENSE" }
  spec.author                = "George Lim"

  spec.platform              = :ios, "10.0"
  spec.ios.deployment_target = "10.0"
  spec.swift_version         = "5.0"

  spec.source                = { :git => "https://github.com/george-lim/envelope.git", :tag => "#{spec.version}" }
  spec.source_files          = "Envelope/**/*.{h,m,swift}"

end
