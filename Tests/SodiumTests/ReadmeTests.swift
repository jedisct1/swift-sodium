import XCTest
import Sodium

class ReadmeTests : XCTestCase {
    static let allTests = [
        ("testAnonymousEncryptionSealedBoxes", testAnonymousEncryptionSealedBoxes),
        ("testAttachedSignatures", testAttachedSignatures),
        ("testAuth", testAuth),
        ("testAuthenticatedEncryption", testAuthenticatedEncryption),
        ("testBase64", testBase64),
        ("testConstantTimeComparison", testConstantTimeComparison),
        ("testConstantTimeHexdecimalEncoding", testConstantTimeHexdecimalEncoding),
        ("testDetachedSignatures", testDetachedSignatures),
        ("testDeterministicHashing", testDeterministicHashing),
        ("testHexDecimalDecoding", testHexDecimalDecoding),
        ("testKeyDerivation", testKeyDerivation),
        ("testKeyedHashing", testKeyedHashing),
        ("testKeyExchange", testKeyExchange),
        ("testPadding", testPadding),
        ("testPasswordHashing", testPasswordHashing),
        ("testRandomNumberGeneration", testRandomNumberGeneration),
        ("testSecretKeyAuthenticatedEncryption", testSecretKeyAuthenticatedEncryption),
        ("testSecretStream", testSecretStream),
        ("testShortOutputHashing", testShortOutputHashing),
        ("testStream", testStream),
        ("testStreaming", testStreaming),
        ("testZeroingMemory", testZeroingMemory),
    ]

    func testAuthenticatedEncryption() {
        let sodium = Sodium()
        let aliceKeyPair = sodium.box.keyPair()!
        let bobKeyPair = sodium.box.keyPair()!
        let message = "My Test Message".bytes

        let encryptedMessageFromAliceToBob: Bytes =
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
        let sodium = Sodium()
        let bobKeyPair = sodium.box.keyPair()!
        let message = "My Test Message".bytes

        let encryptedMessageToBob =
            sodium.box.seal(message: message, recipientPublicKey: bobKeyPair.publicKey)!

        let messageDecryptedByBob =
            sodium.box.open(anonymousCipherText: encryptedMessageToBob,
                            recipientPublicKey: bobKeyPair.publicKey,
                            recipientSecretKey: bobKeyPair.secretKey)

        XCTAssertNotNil(messageDecryptedByBob)
    }

	func testKeyExchange() {
		let sodium = Sodium()
		let aliceKeyPair = sodium.keyExchange.keyPair()!
		let bobKeyPair = sodium.keyExchange.keyPair()!

		let sessionKeyPairForAlice = sodium.keyExchange.sessionKeyPair(publicKey: aliceKeyPair.publicKey,
																	   secretKey: aliceKeyPair.secretKey, otherPublicKey: bobKeyPair.publicKey, side: .CLIENT)!
		let sessionKeyPairForBob = sodium.keyExchange.sessionKeyPair(publicKey: bobKeyPair.publicKey,
																	 secretKey: bobKeyPair.secretKey, otherPublicKey: aliceKeyPair.publicKey, side: .SERVER)!

		let aliceToBobKeyEquality = sodium.utils.equals(sessionKeyPairForAlice.tx, sessionKeyPairForBob.rx) // true
		let bobToAliceKeyEquality = sodium.utils.equals(sessionKeyPairForAlice.rx, sessionKeyPairForBob.tx) // true

		XCTAssertTrue(aliceToBobKeyEquality)
		XCTAssertTrue(bobToAliceKeyEquality)
	}

    func testDetachedSignatures() {
        let sodium = Sodium()
        let message = "My Test Message".bytes
        let keyPair = sodium.sign.keyPair()!
        let signature = sodium.sign.signature(message: message, secretKey: keyPair.secretKey)!
        if sodium.sign.verify(message: message,
                              publicKey: keyPair.publicKey,
                              signature: signature) {
            // signature is valid
        }
    }

    func testAttachedSignatures() {
        let sodium = Sodium()
        let message = "My Test Message".bytes
        let keyPair = sodium.sign.keyPair()!
        let signedMessage = sodium.sign.sign(message: message, secretKey: keyPair.secretKey)!
        if sodium.sign.open(signedMessage: signedMessage, publicKey: keyPair.publicKey) != nil {
            // signature is valid
        }
    }

    func testSecretKeyAuthenticatedEncryption() {
        let sodium = Sodium()
        let message = "My Test Message".bytes
        let secretKey = sodium.secretBox.key()
        let encrypted: Bytes = sodium.secretBox.seal(message: message, secretKey: secretKey)!
        if sodium.secretBox.open(nonceAndAuthenticatedCipherText: encrypted, secretKey: secretKey) != nil {
            // authenticator is valid, decrypted contains the original message
        }
    }

    func testDeterministicHashing() {
        let sodium = Sodium()
        let message = "My Test Message".bytes
        let h = sodium.genericHash.hash(message: message)

        XCTAssertNotNil(h)
    }

    func testKeyedHashing() {
        let sodium = Sodium()
        let message = "My Test Message".bytes
        let key = "Secret key".bytes
        let h = sodium.genericHash.hash(message: message, key: key)

        XCTAssertNotNil(h)
    }

    func testStreaming() {
        let sodium = Sodium()
        let message1 = "My Test ".bytes
        let message2 = "Message".bytes
        let key = "Secret key".bytes
        let stream = sodium.genericHash.initStream(key: key)!
        stream.update(input: message1)
        stream.update(input: message2)
        let h = stream.final()

        XCTAssertNotNil(h)
    }

    func testShortOutputHashing() {
        let sodium = Sodium()
        let message = "My Test Message".bytes
        let key = sodium.randomBytes.buf(length: sodium.shortHash.KeyBytes)!
        let h = sodium.shortHash.hash(message: message, key: key)

        XCTAssertNotNil(h)
    }

    func testRandomNumberGeneration() {
        let sodium = Sodium()
        let randomData = sodium.randomBytes.buf(length: 1000)

        XCTAssertNotNil(randomData)
    }

    func testPasswordHashing() {
        let sodium = Sodium()
        let password = "Correct Horse Battery Staple".bytes
        let hashedStr = sodium.pwHash.str(passwd: password,
                                          opsLimit: sodium.pwHash.OpsLimitInteractive,
                                          memLimit: sodium.pwHash.MemLimitInteractive)!

        if sodium.pwHash.strVerify(hash: hashedStr, passwd: password) {
            // Password matches the given hash string
        } else {
            // Password doesn't match the given hash string
        }

        if sodium.pwHash.strNeedsRehash(hash: hashedStr,
                                        opsLimit: sodium.pwHash.OpsLimitInteractive,
                                        memLimit: sodium.pwHash.MemLimitInteractive) {
            // Previously hashed password should be recomputed because the way it was
            // hashed doesn't match the current algorithm and the given parameters.
        }
    }

    func testZeroingMemory() {
        let sodium = Sodium()
        var dataToZero = "Message".bytes
        sodium.utils.zero(&dataToZero)
    }

    func testConstantTimeComparison() {
        let sodium = Sodium()
        let secret1 = "Secret key".bytes
        let secret2 = "Secret key".bytes
        let equality = sodium.utils.equals(secret1, secret2)

        XCTAssertTrue(equality)
    }

    func testConstantTimeHexdecimalEncoding() {
        let sodium = Sodium()
        let data = "Secret key".bytes
        let hex = sodium.utils.bin2hex(data)

        XCTAssertNotNil(hex)
    }

    func testHexDecimalDecoding() {
        let sodium = Sodium()
        let data1 = sodium.utils.hex2bin("deadbeef")
        let data2 = sodium.utils.hex2bin("de:ad be:ef", ignore: " :")

        XCTAssertNotNil(data1)
        XCTAssertNotNil(data2)
    }

    func testStream() {
        let sodium = Sodium()
        let input = "test".bytes
        let key = sodium.stream.key()
        let (output, nonce) = sodium.stream.xor(input: input, secretKey: key)!
        let twice = sodium.stream.xor(input: output, nonce: nonce, secretKey: key)!

        XCTAssertEqual(input, twice)
    }

    func testAuth() {
        let sodium = Sodium()
        let input = "test".bytes
        let key = sodium.auth.key()
        let tag = sodium.auth.tag(message: input, secretKey: key)!
        let tagIsValid = sodium.auth.verify(message: input, secretKey: key, tag: tag)

        XCTAssertTrue(tagIsValid)
    }

    func testKeyDerivation() {
        let sodium = Sodium()
        let secretKey = sodium.keyDerivation.key()

        let subKey1 = sodium.keyDerivation.derive(secretKey: secretKey,
                                                  index: 0, length: 32,
                                                  context: "Context!")!
        let subKey2 = sodium.keyDerivation.derive(secretKey: secretKey,
                                                  index: 1, length: 32,
                                                  context: "Context!")!
        XCTAssertNotEqual(subKey1, subKey2)
    }

    func testSecretStream() {
        let sodium = Sodium()
        let message1 = "Message 1".bytes
        let message2 = "Message 2".bytes
        let message3 = "Message 3".bytes

        let secretkey = sodium.secretStream.xchacha20poly1305.key()

        /* stream encryption */

        let stream_enc = sodium.secretStream.xchacha20poly1305.initPush(secretKey: secretkey)!
        let header = stream_enc.header()
        let encrypted1 = stream_enc.push(message: message1)!
        let encrypted2 = stream_enc.push(message: message2)!
        let encrypted3 = stream_enc.push(message: message3, tag: .FINAL)!

        /* stream decryption */

        let stream_dec = sodium.secretStream.xchacha20poly1305.initPull(secretKey: secretkey, header: header)!
        let (message1_dec, tag1) = stream_dec.pull(cipherText: encrypted1)!
        let (message2_dec, tag2) = stream_dec.pull(cipherText: encrypted2)!
        let (message3_dec, tag3) = stream_dec.pull(cipherText: encrypted3)!

        XCTAssertEqual(message1, message1_dec)
        XCTAssertEqual(message2, message2_dec)
        XCTAssertEqual(message3, message3_dec)
        XCTAssertEqual(tag1, .MESSAGE)
        XCTAssertEqual(tag2, .MESSAGE)
        XCTAssertEqual(tag3, .FINAL)
    }

    func testBase64() {
        let sodium = Sodium()
        let b64 = sodium.utils.bin2base64("data".bytes)!
        let b64_2 = sodium.utils.bin2base64("data".bytes, variant: .URLSAFE_NO_PADDING)!

        let data1 = sodium.utils.base642bin(b64)
        let data2 = sodium.utils.base642bin(b64, ignore: " \n")
        let data3 = sodium.utils.base642bin(b64_2, variant: .URLSAFE_NO_PADDING, ignore: " \n")

        XCTAssertEqual(data1!, "data".bytes)
        XCTAssertEqual(data2!, "data".bytes)
        XCTAssertEqual(data3!, "data".bytes)
    }

    func testPadding() {
        let sodium = Sodium()
        var data = "test".bytes

        // make data.count a multiple of 16
        sodium.utils.pad(bytes: &data, blockSize: 16)!

        // restore original size
        sodium.utils.unpad(bytes: &data, blockSize: 16)!
    }
}
