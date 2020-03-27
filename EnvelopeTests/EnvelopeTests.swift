//
//  EnvelopeTests.swift
//  EnvelopeTests
//
//  Created by George Lim on 2019-08-02.
//  Copyright © 2019 George Lim. All rights reserved.
//

import XCTest
@testable import Envelope

class EnvelopeTests: XCTestCase {

  // MARK: - AES256CBC tests

  let predictableAES256CBC = try! AES256CBC(password: "password", rounds: 10000, iv: "1234567890123456")
  let bundle = Bundle(for: EnvelopeTests.self)

  func aesSharedSecret(key: String, iv: String) -> CFData {
    return Data("\(key)\n\(iv)".utf8) as CFData
  }

  func testPredictableAES256CBC() {
    do {
      let ciphers = try [
        predictableAES256CBC,
        AES256CBC(password: "XXXXXXXX", rounds: 10000, iv: "1234567890123456"),
        AES256CBC(password: "password", rounds: 10001, iv: "1234567890123456"),
        AES256CBC(password: "password", rounds: 10000, iv: "XXXXXXXXXXXXXXXX"),
        AES256CBC(password: "", rounds: 10000, iv: "1234567890123456")
      ]

      let expectedKeys = [
        "17dab8db64084126762256304ece4d1be9835355078639cae426b53d3b0a141f",
        "65807875deee84a4681d0247ce5450863ac49b6221b02ca69c4184284e822111",
        "8415244ca3a2a5db5bd193255082ef8a7a3e1f18da5990f94ea3effb1f1d9a06",
        "17dab8db64084126762256304ece4d1be9835355078639cae426b53d3b0a141f",
        "7f9894580f4165c8974bb506acb0d86126cfb25258039ef7508c57f82f595be5"
      ]

      let expectedIVs = [
        "31323334353637383930313233343536",
        "31323334353637383930313233343536",
        "31323334353637383930313233343536",
        "58585858585858585858585858585858",
        "31323334353637383930313233343536"
      ]

      for i in 0 ..< ciphers.count {
        XCTAssertTrue(ciphers[i].sharedSecret == aesSharedSecret(key: expectedKeys[i], iv: expectedIVs[i]))
      }
    } catch {
      XCTFail()
    }
  }

  func testRandomAES256CBC() {
    do {
      let ciphers = try [
        AES256CBC(password: "password"),
        AES256CBC(password: "password"),
        AES256CBC(password: "differentPassword"),
        AES256CBC(password: "password", randomSaltLength: 8),
        AES256CBC(password: "password", runtime: 1000),
        AES256CBC(password: "password", randomSaltLength: 8, runtime: 1000),
      ]

      var seenSharedSecrets: [CFData] = []
      ciphers.forEach {
        XCTAssertFalse(seenSharedSecrets.contains($0.sharedSecret))
        seenSharedSecrets.append($0.sharedSecret)
      }
    } catch {
      XCTFail()
    }
  }

  func testAES256CBCCrypt() {
    do {
      let predictableCiphertext = try predictableAES256CBC.encrypt("Hello world!")
      let expectedBase64Ciphertext = "ukx6l+YT0AQKe66fVK/WMA=="
      XCTAssertTrue(predictableCiphertext.base64EncodedString() == expectedBase64Ciphertext)
      XCTAssertTrue(try predictableAES256CBC.decrypt(predictableCiphertext) == "Hello world!")

      let randomAES256CBC = try AES256CBC(password: "password")
      let randomCiphertext = try randomAES256CBC.encrypt("Hello world!")
      XCTAssertFalse(randomCiphertext == predictableCiphertext)
      XCTAssertTrue(try randomAES256CBC.decrypt(randomCiphertext) == "Hello world!")
    } catch {
      XCTFail()
    }
  }

  func testAES256CBCCryptEmptyData() {
    do {
      let randomAES256CBC = try AES256CBC(password: "password")
      let ciphertext = try randomAES256CBC.encrypt(Data())
      XCTAssertFalse(ciphertext == Data())
      let plaintext: Data = try randomAES256CBC.decrypt(ciphertext)
      XCTAssertTrue(plaintext == Data())
    } catch {
      XCTFail()
    }
  }

  func testAES256CBCDecryptInvalidInformation() {
    do {
      let predictableCiphertext = try predictableAES256CBC.encrypt("Hello world!")
      let randomAES256CBC = try AES256CBC(password: "password")
      XCTAssertFalse(try randomAES256CBC.decrypt(predictableCiphertext) == "Hello world!")
    } catch {
      XCTFail()
    }
  }

  func testAES256CBCInvalidInput() {
    do {
      _ = try AES256CBC(password: "password", rounds: 0, iv: "1234567890123456")
      XCTFail()
    } catch let error as AES256CBC.Error {
      guard case .invalidRoundsCount = error else {
        XCTFail()
        return
      }
    } catch {
      XCTFail()
    }

    do {
      _ = try AES256CBC(password: "password", randomSaltLength: 133)
      XCTFail()
    } catch let error as AES256CBC.Error {
      guard case .invalidSaltLength = error else {
        XCTFail()
        return
      }
    } catch {
      XCTFail()
    }

    do {
      _ = try AES256CBC(password: "password", rounds: 10000, iv: "")
      _ = try AES256CBC(password: "password", rounds: 10000, iv: "123456789012345")
      _ = try AES256CBC(password: "password", rounds: 10000, iv: "12345678901234567")
      XCTFail()
    } catch let error as AES256CBC.Error {
      guard case .invalidIVLength = error else {
        XCTFail()
        return
      }
    } catch {
      XCTFail()
    }
  }

  // MARK: - Envelope tests

  func testEnvelope() {
    do {
      _ = try Envelope(derNamed: "certificate", in: bundle, symmetricCipher: predictableAES256CBC)
      _ = try Envelope(derNamed: "certificate", in: bundle, password: "password")
    } catch {
      XCTFail()
    }
  }

  func testEnvelopeInvalidCertificate() {
    do {
      _ = try Envelope(derNamed: "doesNotExist", in: bundle, symmetricCipher: predictableAES256CBC)
      XCTFail()
    } catch let error as Envelope.Error {
      guard case .invalidCertificate = error else {
        XCTFail()
        return
      }
    } catch {
      XCTFail()
    }
  }

  func testEnvelopeCrypt() {
    do {
      let envelope = try Envelope(derNamed: "certificate", in: bundle, symmetricCipher: predictableAES256CBC)
      let ciphertext = try envelope.encrypt("Hello world!")
      let base64CiphertextKey = ciphertext.key.base64EncodedString()
      let base64CiphertextData = ciphertext.data.base64EncodedString()
      let expectedBase64CiphertextData = "ukx6l+YT0AQKe66fVK/WMA=="
      XCTAssertTrue(base64CiphertextData == expectedBase64CiphertextData)
      print("----------------------------------------------------------------")
      print("testEnvelopeCrypt()\nTo decrypt ciphertext, `cd EnvelopeTests` and execute the following bash command:")
      print("set -- $(echo \(base64CiphertextKey) | base64 --decode | openssl rsautl -decrypt -inkey privateKey.pem);echo \(base64CiphertextData) | base64 --decode | openssl aes-256-cbc -K $1 -iv $2 -d")
      print("----------------------------------------------------------------")
    } catch {
      XCTFail()
    }
  }
}
