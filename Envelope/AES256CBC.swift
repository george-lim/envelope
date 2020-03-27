//
//  AES256CBC.swift
//  Envelope
//
//  Created by George Lim on 2019-08-05.
//  Copyright © 2019 George Lim. All rights reserved.
//

import Foundation
import CommonCrypto

public class AES256CBC: SymmetricCipher {

  // MARK: - Constants

  // `CCCalibratePBKDF` upperbound to calculate rounds for AES keygen
  private static let maxSaltLength = 133

  // MARK: - Properties

  private let key: Data
  private let iv: Data

  // MARK: - Shared secret

  public var sharedSecret: CFData {
    return Data("\(key.hexString)\n\(iv.hexString)".utf8) as CFData
  }

  // MARK: - Error handling

  public enum Error: Swift.Error {
    // `SecRandomCopyBytes` failed to generate random bytes
    case randomCopyBytesFailed
    // rounds must be non-zero in `CCKeyDerivationPBKDF`
    case invalidRoundsCount
    // `CCKeyDerivationPBKDF` failed to generate key
    case keygenFailed(status: CCStatus)
    // salt exceeds `maxSaltLength` in `CCCalibratePBKDF`
    case invalidSaltLength
    // key length does not match 256-bit AES key size
    case invalidKeyLength
    // IV length does not match AES block size
    case invalidIVLength
    // `CCCrypt` failed to perform crypt operation
    case cryptFailed(status: CCCryptorStatus)
  }

  // MARK: - Generating random data

  private static func randomBytes(_ count: Int) throws -> Data {
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    guard status == errSecSuccess else { throw Error.randomCopyBytesFailed }
    return data
  }

  private static func randomIV() throws -> Data {
    return try randomBytes(kCCBlockSizeAES128)
  }

  // MARK: - Generating keys

  private static func keygen(using password: Data, salt: Data, rounds: UInt32) throws -> Data {
    guard rounds > 0 else { throw Error.invalidRoundsCount }
    var bytes = [UInt8](repeating: 0, count: kCCKeySizeAES256)

    try password.withUnsafeBytes { passwordBytes in
      try salt.withUnsafeBytes { saltBytes in
        let status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                          passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                                          passwordBytes.count,
                                          saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                          saltBytes.count,
                                          CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                                          rounds,
                                          &bytes,
                                          kCCKeySizeAES256)
        guard status == kCCSuccess else { throw Error.keygenFailed(status: status) }
      }
    }

    return Data(bytes: UnsafePointer<UInt8>(bytes), count: kCCKeySizeAES256)
  }

  private static func keygen(using password: Data, salt: Data, runtime: UInt32) throws -> Data {
    guard salt.count < maxSaltLength else { throw Error.invalidSaltLength }
    let rounds = CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                  password.count,
                                  salt.count,
                                  CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                                  kCCKeySizeAES256,
                                  runtime)
    return try keygen(using: password, salt: salt, rounds: rounds)
  }

  // MARK: - Initializers

  private init(key: Data, iv: Data) throws {
    guard key.count == kCCKeySizeAES256 else { throw Error.invalidKeyLength }
    guard iv.count == kCCBlockSizeAES128 else { throw Error.invalidIVLength }
    self.key = key
    self.iv = iv
  }

  #if DEBUG
  // (FOR TESTING ONLY) Guarantees same shared secret
  public convenience init(password: String, rounds: UInt32 = 10000, iv: String) throws {
    let key = try AES256CBC.keygen(using: Data(password.utf8), salt: Data(), rounds: rounds)
    try self.init(key: key, iv: Data(iv.utf8))
  }
  #endif

  // Generates random shared secret
  // AES keygen runs for `runtime` (in ms) and generates key from `password` and random salt
  public convenience init(password: String, randomSaltLength: Int = 32, runtime: UInt32 = 500) throws {
    let salt = try AES256CBC.randomBytes(randomSaltLength)
    let key = try AES256CBC.keygen(using: Data(password.utf8), salt: salt, runtime: runtime)
    let iv = try AES256CBC.randomIV()
    try self.init(key: key, iv: iv)
  }

  // MARK: - Crypt methods

  private func crypt(_ data: Data, operation: CCOperation) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
    var length = 0

    try data.withUnsafeBytes { dataBytes in
      try key.withUnsafeBytes { keyBytes in
        try iv.withUnsafeBytes { ivBytes in
          let status = CCCrypt(operation,
                               CCAlgorithm(kCCAlgorithmAES),
                               CCOptions(kCCOptionPKCS7Padding),
                               keyBytes.baseAddress,
                               keyBytes.count,
                               ivBytes.baseAddress,
                               dataBytes.baseAddress,
                               dataBytes.count,
                               &bytes,
                               bytes.count,
                               &length)
          guard status == kCCSuccess else { throw Error.cryptFailed(status: status) }
        }
      }
    }

    return Data(bytes: UnsafePointer<UInt8>(bytes), count: length)
  }

  public func encrypt(_ plaintext: Data) throws -> Data {
    return try crypt(plaintext, operation: CCOperation(kCCEncrypt))
  }

  public func decrypt(_ ciphertext: Data) throws -> Data {
    return try crypt(ciphertext, operation: CCOperation(kCCDecrypt))
  }
}
