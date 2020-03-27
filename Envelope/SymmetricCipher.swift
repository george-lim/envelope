//
//  SymmetricCipher.swift
//  Envelope
//
//  Created by George Lim on 2019-08-02.
//  Copyright © 2019 George Lim. All rights reserved.
//

import Foundation

public protocol SymmetricCipher {
  var sharedSecret: CFData { get }

  func encrypt(_ plaintext: Data) throws -> Data
  func decrypt(_ ciphertext: Data) throws -> Data

  func encrypt(_ plaintext: String) throws -> Data
  func decrypt(_ ciphertext: Data) throws -> String?
}

public extension SymmetricCipher {
  func encrypt(_ plaintext: String) throws -> Data {
    return try encrypt(Data(plaintext.utf8))
  }

  func decrypt(_ ciphertext: Data) throws -> String? {
    return try String(data: decrypt(ciphertext), encoding: .utf8)
  }
}
