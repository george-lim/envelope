//
//  Envelope.swift
//  Envelope
//
//  Created by George Lim on 2019-08-02.
//  Copyright © 2019 George Lim. All rights reserved.
//

import Foundation
import CommonCrypto

public class Envelope {

  // MARK: - Properties

  private let publicKey: SecKey
  private let algorithm: SecKeyAlgorithm
  private let symmetricCipher: SymmetricCipher

  // MARK: - Error handling

  public enum Error: Swift.Error {
    // X.509 certificate could not be imported
    case invalidCertificate
  }

  // MARK: - Ciphertext structure

  public struct Ciphertext {
    // Contains symmetric cipher shared secret (encrypted with public-key)
    public let key: Data
    // Contains plaintext (encrypted with symmetric cipher shared secret)
    public let data: Data
  }

  // MARK: - Importing public-key

  // CommonCrypto rejects all externally created public-keys
  // Workaround by importing public-key from a DER encoded X.509 certificate
  private static func publicKey(derNamed certificate: String, in bundle: Bundle) throws -> SecKey {
    var secTrust: SecTrust?
    var unusedResultType: SecTrustResultType = .invalid
    guard let url = bundle.url(forResource: certificate, withExtension: "der"),
      let certificateData = try? Data(contentsOf: url) as CFData,
      let certificate = SecCertificateCreateWithData(nil, certificateData),
      SecTrustCreateWithCertificates(certificate, nil, &secTrust) == errSecSuccess,
      SecTrustEvaluate(secTrust!, &unusedResultType) == errSecSuccess,
      let publicKey = SecTrustCopyPublicKey(secTrust!) else { throw Error.invalidCertificate }
    return publicKey
  }

  // MARK: - Initializers

  // Generic initializer for any `SymmetricCipher` implementation
  public init(derNamed certificate: String, in bundle: Bundle, algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1, symmetricCipher: SymmetricCipher) throws {
    publicKey = try Envelope.publicKey(derNamed: certificate, in: bundle)
    self.algorithm = algorithm
    self.symmetricCipher = symmetricCipher
  }

  // Initializer for `AES256CBC` implementation
  public convenience init(derNamed certificate: String, in bundle: Bundle = .main, algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1, password: String, randomSaltLength: Int = 32, runtime: UInt32 = 500) throws {
    let symmetricCipher = try AES256CBC(password: password, randomSaltLength: randomSaltLength, runtime: runtime)
    try self.init(derNamed: certificate, in: bundle, algorithm: algorithm, symmetricCipher: symmetricCipher)
  }

  // MARK: - Crypt methods

  public func encrypt(_ plaintext: Data) throws -> Ciphertext {
    let ciphertextData = try symmetricCipher.encrypt(plaintext)
    var error: Unmanaged<CFError>?
    guard let ciphertextKey = SecKeyCreateEncryptedData(publicKey, algorithm, symmetricCipher.sharedSecret, &error) as Data? else {
      throw error!.takeRetainedValue()
    }
    return Ciphertext(key: ciphertextKey, data: ciphertextData)
  }

  public func encrypt(_ plaintext: String) throws -> Ciphertext {
    return try encrypt(Data(plaintext.utf8))
  }
}
