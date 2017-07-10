//
//  ReadmeTests.swift
//  Sodium
//
//  Created by Joseph Ross on 1/8/17.
//  Copyright © 2017 Joseph Ross. All rights reserved.
//

import XCTest
import Sodium

class ReadmeTests : XCTestCase {
    func testAuthenticatedEncryption() {
        let sodium = Sodium()!
        let aliceKeyPair = sodium.box.keyPair()!
        let bobKeyPair = sodium.box.keyPair()!
        let message = "My Test Message".data(using:.utf8)!

        let encryptedMessageFromAliceToBob: Data =
            sodium.box.seal(message: message,
                            recipientPublicKey: bobKeyPair.publicKey,
                            senderSecretKey: aliceKeyPair.secretKey)!

        let messageVerifiedAndDecryptedByBob =
            sodium.box.open(nonceAndAuthenticatedCipherText: encryptedMessageFromAliceToBob,
                            senderPublicKey: aliceKeyPair.publicKey,
                            recipientSecretKey: bobKeyPair.secretKey)

        XCTAssertNotNil(messageVerifiedAndDecryptedByBob)
    }

    func testAnonymousEncryptionSealedBoxes() {
        let sodium = Sodium()!
        let bobKeyPair = sodium.box.keyPair()!
        let message = "My Test Message".data(using:.utf8)!

        let encryptedMessageToBob =
            sodium.box.seal(message: message, recipientPublicKey: bobKeyPair.publicKey)!

        let messageDecryptedByBob =
            sodium.box.open(anonymousCipherText: encryptedMessageToBob,
                            recipientPublicKey: bobKeyPair.publicKey,
                            recipientSecretKey: bobKeyPair.secretKey)

        XCTAssertNotNil(messageDecryptedByBob)
    }

    func testDetachedSignatures() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let keyPair = sodium.sign.keyPair()!
        let signature = sodium.sign.signature(message: message, secretKey: keyPair.secretKey)!
        if sodium.sign.verify(message: message,
                              publicKey: keyPair.publicKey,
                              signature: signature) {
            // signature is valid
        }
    }

    func testAttachedSignatures() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let keyPair = sodium.sign.keyPair()!
        let signedMessage = sodium.sign.sign(message: message, secretKey: keyPair.secretKey)!
        if let unsignedMessage = sodium.sign.open(signedMessage: signedMessage, publicKey: keyPair.publicKey) {
            // signature is valid
        }
    }

    func testSecretKeyAuthenticatedEncryption() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let secretKey = sodium.secretBox.key()!
        let encrypted: Data = sodium.secretBox.seal(message: message, secretKey: secretKey)!
        if let decrypted = sodium.secretBox.open(nonceAndAuthenticatedCipherText: encrypted, secretKey: secretKey) {
            // authenticator is valid, decrypted contains the original message
        }
    }

    func testDeterministicHashing() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let h = sodium.genericHash.hash(message: message)

        XCTAssertNotNil(h)
    }

    func testKeyedHashing() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let key = "Secret key".data(using:.utf8)!
        let h = sodium.genericHash.hash(message: message, key: key)

        XCTAssertNotNil(h)
    }

    func testStreaming() {
        let sodium = Sodium()!
        let message1 = "My Test ".data(using:.utf8)!
        let message2 = "Message".data(using:.utf8)!
        let key = "Secret key".data(using:.utf8)!
        let stream = sodium.genericHash.initStream(key: key)!
        stream.update(input: message1)
        stream.update(input: message2)
        let h = stream.final()

        XCTAssertNotNil(h)
    }

    func testShortOutputHashing() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let key = sodium.randomBytes.buf(length: sodium.shortHash.KeyBytes)!
        let h = sodium.shortHash.hash(message: message, key: key)

        XCTAssertNotNil(h)
    }

    func testRandomNumberGeneration() {
        let sodium = Sodium()!
        let randomData = sodium.randomBytes.buf(length: 1000)

        XCTAssertNotNil(randomData)
    }

    func testPasswordHashing() {
        let sodium = Sodium()!
        let password = "Correct Horse Battery Staple".data(using:.utf8)!
        let hashedStr = sodium.pwHash.str(passwd: password,
                                          opsLimit: sodium.pwHash.OpsLimitInteractive,
                                          memLimit: sodium.pwHash.MemLimitInteractive)!

        if sodium.pwHash.strVerify(hash: hashedStr, passwd: password) {
            // Password matches the given hash string
        } else {
            // Password doesn't match the given hash string
        }
    }

    func testZeroingMemory() {
        let sodium = Sodium()!
        var dataToZero = "Message".data(using:.utf8)!
        sodium.utils.zero(&dataToZero)
    }

    func testConstantTimeComparison() {
        let sodium = Sodium()!
        let secret1 = "Secret key".data(using:.utf8)!
        let secret2 = "Secret key".data(using:.utf8)!
        let equality = sodium.utils.equals(secret1, secret2)

        XCTAssertTrue(equality)
    }

    func testConstantTimeHexdecimalEncoding() {
        let sodium = Sodium()!
        let data = "Secret key".data(using:.utf8)!
        let hex = sodium.utils.bin2hex(data)

        XCTAssertNotNil(hex)
    }

    func testHexDecimalDecoding() {
        let sodium = Sodium()!
        let data1 = sodium.utils.hex2bin("deadbeef")
        let data2 = sodium.utils.hex2bin("de:ad be:ef", ignore: " :")

        XCTAssertNotNil(data1)
        XCTAssertNotNil(data2)
    }

    func testStream() {
        let sodium = Sodium()!
        let input = "test".data(using:.utf8)!
        let key = sodium.stream.key()!;
        let (output, nonce) = sodium.stream.xor(input: input, secretKey: key)!
        let twice = sodium.stream.xor(input: output, nonce: nonce, secretKey: key)!

        XCTAssertEqual(input, twice)
    }

    func testAuth() {
        let sodium = Sodium()!
        let input = "test".data(using:.utf8)!
        let key = sodium.auth.key()!;
        let tag = sodium.auth.tag(message: input, secretKey: key)!
        let tagIsValid = sodium.auth.verify(message: input, secretKey: key, tag: tag)

        XCTAssertTrue(tagIsValid)
    }

    func testKeyDerivation() {
        let sodium = Sodium()!
        let secretKey = sodium.keyDerivation.keygen()!

        let subKey1 = sodium.keyDerivation.derive(secretKey: secretKey,
            index: 0, length: 32,
            context: "Context!")!
        let subKey2 = sodium.keyDerivation.derive(secretKey: secretKey,
            index: 1, length: 32,
            context: "Context!")!
    }
}
