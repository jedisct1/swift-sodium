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
        
        let encryptedMessageFromAliceToBob: NSData =
            sodium.box.seal(message: message as NSData,
                            recipientPublicKey: bobKeyPair.publicKey,
                            senderSecretKey: aliceKeyPair.secretKey)!
        
        let messageVerifiedAndDecryptedByBob =
            sodium.box.open(nonceAndAuthenticatedCipherText: encryptedMessageFromAliceToBob,
                            senderPublicKey: aliceKeyPair.publicKey,
                            recipientSecretKey: bobKeyPair.secretKey)
    }
    
    func testAnonymousEncryptionSealedBoxes() {
        let sodium = Sodium()!
        let bobKeyPair = sodium.box.keyPair()!
        let message = "My Test Message".data(using:.utf8)!
        
        let encryptedMessageToBob =
            sodium.box.seal(message: message as NSData, recipientPublicKey: bobKeyPair.publicKey)!
        
        let messageDecryptedByBob =
            sodium.box.open(anonymousCipherText: encryptedMessageToBob,
                            recipientPublicKey: bobKeyPair.publicKey,
                            recipientSecretKey: bobKeyPair.secretKey)
    }
    
    func testDetachedSignatures() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let keyPair = sodium.sign.keyPair()!
        let signature = sodium.sign.signature(message: message as NSData, secretKey: keyPair.secretKey)!
        if sodium.sign.verify(message: message as NSData,
                              publicKey: keyPair.publicKey,
                              signature: signature) {
            // signature is valid
        }
    }
    
    func testAttachedSignatures() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let keyPair = sodium.sign.keyPair()!
        let signedMessage = sodium.sign.sign(message: message as NSData, secretKey: keyPair.secretKey)!
        if let unsignedMessage = sodium.sign.open(signedMessage: signedMessage, publicKey: keyPair.publicKey) {
            // signature is valid
        }
    }
    
    func testSecretKeyAuthenticatedEncryption() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let secretKey = sodium.secretBox.key()!
        let encrypted: NSData = sodium.secretBox.seal(message: message as NSData, secretKey: secretKey)!
        if let decrypted = sodium.secretBox.open(nonceAndAuthenticatedCipherText: encrypted, secretKey: secretKey) {
            // authenticator is valid, decrypted contains the original message
        }
    }
    
    func testDeterministicHashing() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let h = sodium.genericHash.hash(message: message as NSData)
    }
    
    func testKeyedHashing() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let key = "Secret key".data(using:.utf8)!
        let h = sodium.genericHash.hash(message: message as NSData, key: key as NSData)
    }
    
    func testStreaming() {
        let sodium = Sodium()!
        let message1 = "My Test ".data(using:.utf8)!
        let message2 = "Message".data(using:.utf8)!
        let key = "Secret key".data(using:.utf8)!
        let stream = sodium.genericHash.initStream(key: key as NSData)!
        stream.update(input: message1 as NSData)
        stream.update(input: message2 as NSData)
        let h = stream.final()
    }
    
    func testShortOutputHashing() {
        let sodium = Sodium()!
        let message = "My Test Message".data(using:.utf8)!
        let key = sodium.randomBytes.buf(length: sodium.shortHash.KeyBytes)!
        let h = sodium.shortHash.hash(message: message as NSData, key: key as NSData)
    }
    
    func testRandomNumberGeneration() {
        let sodium = Sodium()!
        let randomData = sodium.randomBytes.buf(length: 1000)
    }
    
    func testPasswordHashing() {
        let sodium = Sodium()!
        let password = "Correct Horse Battery Staple".data(using:.utf8)!
        let hashedStr = sodium.pwHash.str(passwd: password as NSData,
                                          opsLimit: sodium.pwHash.OpsLimitInteractive,
                                          memLimit: sodium.pwHash.MemLimitInteractive)!
        
        if sodium.pwHash.strVerify(hash: hashedStr, passwd: password as NSData) {
            // Password matches the given hash string
        } else {
            // Password doesn't match the given hash string
        }
    }
    
    func testZeroingMemory() {
        let sodium = Sodium()!
        var dataToZero: NSMutableData = NSMutableData(data:"Message".data(using:.utf8)!)
        sodium.utils.zero(data: dataToZero)
    }
    
    func testConstantTimeComparison() {
        let sodium = Sodium()!
        let secret1: NSData = NSData(data:"Secret key".data(using:.utf8)!)
        let secret2: NSData = NSData(data:"Secret key".data(using:.utf8)!)
        let equality = sodium.utils.equals(b1: secret1, secret2)
    }
    
    func testConstantTimeHexdecimalEncoding() {
        let sodium = Sodium()!
        let data: NSData = NSData(data:"Secret key".data(using:.utf8)!)
        let hex = sodium.utils.bin2hex(bin: data)
    }
    
    func testHexDecimalDecoding() {
        let sodium = Sodium()!
        let data1 = sodium.utils.hex2bin(hex: "deadbeef")
        let data2 = sodium.utils.hex2bin(hex: "de:ad be:ef", ignore: " :")
    }
}
