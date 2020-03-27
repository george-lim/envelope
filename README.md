Envelope
=========
[![CI](https://github.com/george-lim/envelope/workflows/CI/badge.svg)](https://github.com/george-lim/envelope/actions)
[![CocoaPods](https://img.shields.io/cocoapods/v/Envelope)](https://cocoapods.org/pods/envelope)
[![Carthage](https://img.shields.io/badge/Carthage-compatible-brightgreen)](https://github.com/Carthage/Carthage)
[![Platforms](https://img.shields.io/cocoapods/p/Envelope)](#)
[![License](https://img.shields.io/github/license/george-lim/envelope)](https://github.com/george-lim/envelope/blob/master/LICENSE)

**OpenSSL-compatible file encryption in Swift**

Envelope is a [hybrid cryptosystem](https://en.wikipedia.org/wiki/Hybrid_cryptosystem) that encrypts files efficiently and securely, supporting most symmetric and [public-key ciphers](https://developer.apple.com/documentation/security/seckeyalgorithm). Envelope uses `AES256-CBC` and `RSA-2048` by default, and supports externally created (ie. OpenSSL) public-keys.

Envelope is used in [TunnelBear](https://apps.apple.com/us/app/tunnelbear-vpn-wifi-proxy/id564842283) as a fallback method to send app logs via email when servers are unreachable.

[Hybrid Encryption](#hybrid-encryption)
| [Features](#features)
| [Installation](#installation)
| [Usage](#usage)
| [License](#license)

## Hybrid Encryption
Public-key ciphers (ie. RSA) are generally slow, inefficient, and have a plaintext size limit. Symmetric ciphers (ie. AES) require secure key exchange, which may not always be possible. Hybrid cryptosystems use both types of ciphers in tandem to efficiently encrypt plaintext, without requiring secure key exchange.

Envelope removes the need for developers to import big cryptography frameworks like [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift) **and** [SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA) just to encrypt files using a single symmetric/public-key cipher pair.

## Features
* No third-party dependencies
* Supports externally created public-key, by importing an `X.509 certificate`
* Supports many [public-key ciphers](https://developer.apple.com/documentation/security/seckeyalgorithm)
* Lightweight implementation of `AES256-CBC` with automatic salt + IV randomization, key generation
* Supports custom symmetric cipher implementations
* Easy integration into existing projects
* Cryptography logic derived from Apple's reliable `CommonCrypto` library

## Installation
Envelope can be installed using CocoaPods, Carthage or by embedding the framework directly into your app from the latest [GitHub release](https://github.com/george-lim/envelope/releases).

### CocoaPods
```
pod 'Envelope'
```

### Carthage
```
github "george-lim/envelope"
```

Once installed, you'll need to import an `X.509 certificate` into your app.

To create a new `RSA-2048` public-key + certificate, execute the following in Terminal:
```
openssl req -newkey rsa:2048 -nodes -keyout privateKey.pem -x509 -out certificate.pem
openssl x509 -outform der -in certificate.pem -out certificate.der
```

Then drag and drop `certificate.der` into your app, making sure to check off `Copy items if needed` and select `Create groups`.

## Usage

### Envelope Encryption
```
// Uses `password` and a random 32-character salt for key generation, and random IV
let defaultEnvelope = try Envelope(derNamed: "certificate", password: "some AES password")

// Support for custom bundle where certificate is stored, public-key algorithm, random salt length, and AES keygen runtime (in ms)
let customEnvelope = try Envelope(derNamed: "certificate",
                                  in: Bundle.main,
                                  algorithm: .rsaEncryptionPKCS1,
                                  password: "some AES password",
                                  randomSaltLength: 8,
                                  runtime: 1000)

// Support for `String` or `Data` plaintext
let ciphertext = try defaultEnvelope.encrypt("Hello world!")

// Send ciphertext.key and ciphertext.data to server for decryption
print(ciphertext.key)
print(ciphertext.data)
```

### Envelope Decryption
Assuming you have a folder with `privateKey.pem`, `ciphertext.key` and `ciphertext.data` inside, execute the following in Terminal:
```
set -- $(openssl rsautl -decrypt -inkey privateKey.pem -in ciphertext.key)
openssl aes-256-cbc -K $1 -iv $2 -d -in ciphertext.data out plaintext
```

### AES256-CBC Crypt Operations
Because Envelope includes an `AES256-CBC` implementation, it can be used to perform crypt operations on `String` or `Data` plaintext as well.
```
let aes = try AES256CBC(password: "some AES password")
let ciphertext = try aes.encrypt("Hello world!")
if let plaintext: String = try aes.decrypt(ciphertext) {
  print(plaintext) // Hello world!
}
```

### Custom Symmetric Cipher
Envelope supports custom symmetric ciphers through the `SymmetricCipher` protocol.

Example:
```
class CustomCipher: SymmetricCipher {
  var sharedSecret: CFData {
    return ...
  }

  func encrypt(_ plaintext: Data) throws -> Data {
    ...
  }

  func decrypt(_ ciphertext: Data) throws -> Data {
    ...
  }
}

let symmetricCipher = CustomCipher()
let envelope = try Envelope(derNamed: "certificate", symmetricCipher: symmetricCipher)
let ciphertext = try envelope.encrypt("Hello world!")
```

## License
This project is copyrighted under the MIT license. Complete license can be found here: https://github.com/george-lim/envelope/blob/master/LICENSE
