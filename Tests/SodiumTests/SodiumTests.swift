import XCTest
import Sodium

extension String {
    func toData() -> Data? {
        return self.data(using: .utf8, allowLossyConversion: false)
    }
}

extension Data {
    func toString() -> String? {
        return String(data: self, encoding: .utf8)
    }
}

class SodiumTests: XCTestCase {
    static let allTests = [
        ("testAuth", testAuth),
        ("testBase64", testBase64),
        ("testBox", testBox),
        ("testGenericHash", testGenericHash),
        ("testKeyDerivation", testKeyDerivation),
        ("testKeyDerivationContextTooLong", testKeyDerivationContextTooLong),
        ("testKeyDerivationInputKeyTooLong", testKeyDerivationInputKeyTooLong),
        ("testKeyDerivationInputKeyTooShort", testKeyDerivationInputKeyTooShort),
        ("testKeyDerivationRegression", testKeyDerivationRegression),
        ("testKeyDerivationSubKeyTooLong", testKeyDerivationSubKeyTooLong),
        ("testKeyDerivationSubKeyTooShort", testKeyDerivationSubKeyTooShort),
        ("testKeyExchange", testKeyExchange),
        ("testPad", testPad),
        ("testPwHash", testPwHash),
        ("testRandomBytes", testRandomBytes),
        ("testSHA256Hash", testSHA256Hash),
        ("testSHA512Hash", testSHA512Hash),
        ("testSecretBox", testSecretBox),
        ("testSecretStream", testSecretStream),
        ("testShortHash", testShortHash),
        ("testSignature", testSignature),
        ("testStream", testStream),
        ("testUtils", testUtils),
        ("testRFC8032Vector1", testRFC8032Vector1),
        ("testRFC8032Vector2", testRFC8032Vector2),
        ("testRFC8032Vector3", testRFC8032Vector3),
        ("testRFC8032VectorSHAABC", testRFC8032VectorSHAABC),
    ]

    let sodium = Sodium()

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testBox() {
        let message = "My Test Message".bytes
        let aliceKeyPair = sodium.box.keyPair()!
        let bobKeyPair = sodium.box.keyPair()!

        let encryptedMessageFromAliceToBob: Bytes = sodium.box.seal(message: message, recipientPublicKey: bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey)!
        let decrypted = sodium.box.open(nonceAndAuthenticatedCipherText: encryptedMessageFromAliceToBob, senderPublicKey: bobKeyPair.publicKey, recipientSecretKey: aliceKeyPair.secretKey)
        XCTAssertEqual(decrypted!, message)

        let (encryptedMessageFromAliceToBob2, nonce): (Bytes, Box.Nonce) = sodium.box.seal(message: message, recipientPublicKey: bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey)!
        let decrypted2 = sodium.box.open(authenticatedCipherText: encryptedMessageFromAliceToBob2, senderPublicKey: aliceKeyPair.publicKey, recipientSecretKey: bobKeyPair.secretKey, nonce: nonce)
        XCTAssertEqual(decrypted2!, message)

        let (encryptedMessageFromAliceToBob3, nonce2, mac): (Bytes, Box.Nonce, Box.MAC) = sodium.box.seal(message: message, recipientPublicKey: bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey)!
        let decrypted3 = sodium.box.open(authenticatedCipherText: encryptedMessageFromAliceToBob3, senderPublicKey: aliceKeyPair.publicKey, recipientSecretKey: bobKeyPair.secretKey, nonce: nonce2, mac: mac)
        XCTAssertEqual(decrypted3!, message)

        let userNonce = sodium.randomBytes.buf(length: sodium.box.NonceBytes)!
        let encryptedMessageFromAliceToBob4: Bytes = sodium.box.seal(message: message, recipientPublicKey: bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey, nonce: userNonce)!
        let decrypted4 = sodium.box.open(authenticatedCipherText: encryptedMessageFromAliceToBob4, senderPublicKey: bobKeyPair.publicKey, recipientSecretKey: aliceKeyPair.secretKey, nonce: userNonce)
        XCTAssertEqual(message, decrypted4!)

        let encryptedMessageToBob: Bytes = sodium.box.seal(message: message, recipientPublicKey: bobKeyPair.publicKey)!
        let decrypted5 = sodium.box.open(anonymousCipherText: encryptedMessageToBob, recipientPublicKey: bobKeyPair.publicKey,
                                         recipientSecretKey: bobKeyPair.secretKey)
        XCTAssertEqual(decrypted5!, message)

        // beforenm tests
        // The two beforenm keys calculated by Alice and Bob separately should be identical
        let aliceBeforenm = sodium.box.beforenm(recipientPublicKey: bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey)!
        let bobBeforenm = sodium.box.beforenm(recipientPublicKey: aliceKeyPair.publicKey, senderSecretKey: bobKeyPair.secretKey)!
        XCTAssertEqual(aliceBeforenm, bobBeforenm)

        // Make sure the encryption using beforenm works
        let encryptedMessageBeforenm: Bytes = sodium.box.seal(message: message, beforenm: aliceBeforenm)!
        let decryptedBeforenm = sodium.box.open(nonceAndAuthenticatedCipherText: encryptedMessageBeforenm, beforenm: aliceBeforenm)
        XCTAssertEqual(decryptedBeforenm!, message)

        let (encryptedMessageBeforenm2, nonceBeforenm): (Bytes, Box.Nonce) = sodium.box.seal(message: message, beforenm: aliceBeforenm)!
        let decryptedBeforenm2 = sodium.box.open(authenticatedCipherText: encryptedMessageBeforenm2, beforenm: aliceBeforenm, nonce: nonceBeforenm)
        XCTAssertEqual(decryptedBeforenm2!, message)
    }

    func testSecretBox() {
        let message = "My Test Message".bytes
        let secretKey = sodium.secretBox.key()

        // test simple nonce + mac + message box
        let encrypted: Bytes = sodium.secretBox.seal(message: message, secretKey: secretKey)!
        let decrypted = sodium.secretBox.open(nonceAndAuthenticatedCipherText: encrypted, secretKey: secretKey)!
        XCTAssertEqual(decrypted, message)

        XCTAssertNotEqual(sodium.secretBox.seal(message: message, secretKey: secretKey)!, encrypted, "Ciphertext of two encryption operations on the same plaintext shouldn't be equal. Make sure the nonce was used only once!")

        XCTAssertNil(sodium.secretBox.open(nonceAndAuthenticatedCipherText: encrypted, secretKey: sodium.secretBox.key()), "Shouldn't be able to decrypt with a bad key")

        // test (mac + message, nonce) box
        let (encrypted2, nonce2) = sodium.secretBox.seal(message: message, secretKey: secretKey)!
        let decrypted2 = sodium.secretBox.open(authenticatedCipherText: encrypted2, secretKey: secretKey, nonce: nonce2)
        XCTAssertEqual(decrypted2!, message)

        XCTAssertNil(sodium.secretBox.open(authenticatedCipherText: encrypted2, secretKey: secretKey, nonce: sodium.secretBox.nonce()), "Shouldn't be able to decrypt with an invalid nonce")

        // test (message, nonce, mac) box
        let (encrypted3, nonce3, mac3) = sodium.secretBox.seal(message: message, secretKey: secretKey)!
        let decrypted3 = sodium.secretBox.open(cipherText: encrypted3, secretKey: secretKey, nonce: nonce3, mac: mac3)
        XCTAssertEqual(decrypted3!, message)

        let (encrypted4, nonce4, mac4) = sodium.secretBox.seal(message: message, secretKey: secretKey)!
        XCTAssertNil(sodium.secretBox.open(cipherText: encrypted4, secretKey: secretKey, nonce: nonce3, mac: mac4), "Shouldn't be able to decrypt with an invalid MAC")
        XCTAssertNil(sodium.secretBox.open(cipherText: encrypted4, secretKey: secretKey, nonce: nonce4, mac: mac3), "Shouldn't be able to decrypt with an invalid nonce")

        // reproduce encryption result with user-provided nonce
        let encrypted5 = sodium.secretBox.seal(message: message, secretKey: secretKey, nonce: nonce2)!
        XCTAssertEqual(encrypted5, encrypted2)
    }

    func testGenericHash() {
        let message = "My Test Message".bytes
        let h1 = sodium.utils.bin2hex(sodium.genericHash.hash(message: message)!)!
        XCTAssertEqual(h1, "64a9026fca646c31df54426ad15a341e2444d8a1863d57eb27abecf239609f75")

        let key = sodium.utils.hex2bin("64 a9 02 6f ca 64 6c 31 df 54", ignore: " ")
        let h2 = sodium.utils.bin2hex(sodium.genericHash.hash(message: message, key: key)!)!
        XCTAssertEqual(h2, "1773f324cba2e7b0017e32d7e44f7afd1036c5d4ef9a80ae0e52e95a629844cd")

        let h3 = sodium.utils.bin2hex(sodium.genericHash.hash(message: message, key: key, outputLength: sodium.genericHash.BytesMax)!)!
        XCTAssertEqual(h3, "cba85e39f2d03923b2f66aba99b204333edc34a8443ab1700f7920c7abcc6639963a953f35162a520b21072ab906457d21f1645e6e3985858ee95a84d0771f07")

        let s1 = sodium.genericHash.initStream()!
        XCTAssertTrue(s1.update(input: message))
        let h4 = sodium.utils.bin2hex(s1.final()!)!
        XCTAssertEqual(h4, h1)

        let s2 = sodium.genericHash.initStream(key: key, outputLength: sodium.genericHash.Bytes)!
        XCTAssertTrue(s2.update(input: message))
        let h5 = sodium.utils.bin2hex(s2.final()!)!
        XCTAssertEqual(h5, h2)

        let s3 = sodium.genericHash.initStream(key: key, outputLength: sodium.genericHash.BytesMax)!
        XCTAssertTrue(s3.update(input: message))
        let h6 = sodium.utils.bin2hex(s3.final()!)!
        XCTAssertEqual(h6, h3)
    }

    func testRandomBytes() {
        let randomLen = 100 + Int(sodium.randomBytes.uniform(upperBound: 100))
        let random1 = sodium.randomBytes.buf(length: randomLen)!
        let random2 = sodium.randomBytes.buf(length: randomLen)!
        XCTAssertEqual(random1.count, randomLen)
        XCTAssertEqual(random2.count, randomLen)
        XCTAssertNotEqual(random1, random2)

        var c1 = 0
        let ref1 = self.sodium.randomBytes.random()
        for _ in (0..<100) {
            if sodium.randomBytes.random() == ref1 {
                c1 += 1
            }
        }
        XCTAssert(c1 < 10)

        var c2 = 0
        let ref2 = self.sodium.randomBytes.uniform(upperBound: 100_000)
        for _ in (0..<100) {
            if sodium.randomBytes.uniform(upperBound: 100_000) == ref2 {
                c2 += 1
            }
        }
        XCTAssert(c2 < 10)

        let seed = sodium.utils.hex2bin("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff", ignore: " ")!
        let randomd = sodium.utils.bin2hex(sodium.randomBytes.deterministic(length: 10, seed: seed)!)!
        XCTAssertEqual(randomd, "444dc0602207c270b93f")
        
        var c3 = 0
        var rng = RandomBytes.Generator()
        let ref3 = UInt32.random(in: 0...UInt32.max, using: &rng)
        for _ in (0..<100) {
            if UInt32.random(in: 0...UInt32.max, using: &rng) == ref3 {
                c3 += 1
            }
        }
        XCTAssert(c3 < 10)
    }

    func testShortHash() {
        let message = "My Test Message".bytes
        let key = sodium.utils.hex2bin("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff", ignore: " ")!
        let h = sodium.utils.bin2hex(sodium.shortHash.hash(message: message, key: key)!)!
        XCTAssertEqual(h, "bb9be85c918015ea")
    }

    func testSignature() {
        let message = "My Test Message".bytes
        let keyPair = sodium.sign.keyPair(seed: sodium.utils.hex2bin("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff", ignore: " ")!)!
        let signedMessage = sodium.sign.sign(message: message, secretKey: keyPair.secretKey)!
        XCTAssertEqual(sodium.utils.bin2hex(signedMessage)!, "ce8437d58a27c4d91426d35b24cfaf1e49f95b213c15eddb198f4a8d24c0fdd0df3e7f7a894f60ec15cff25b5f6f27399ce01db0e2649fc54c91cafb8dd48a094d792054657374204d657373616765")

        let signature = sodium.sign.signature(message: message, secretKey: keyPair.secretKey)!
        XCTAssertEqual(sodium.utils.bin2hex(signature)!, "ce8437d58a27c4d91426d35b24cfaf1e49f95b213c15eddb198f4a8d24c0fdd0df3e7f7a894f60ec15cff25b5f6f27399ce01db0e2649fc54c91cafb8dd48a09")

        XCTAssertTrue(sodium.sign.verify(signedMessage: signedMessage, publicKey: keyPair.publicKey))
        XCTAssertTrue(sodium.sign.verify(message: message, publicKey: keyPair.publicKey, signature: signature))

        let unsignedMessage = sodium.sign.open(signedMessage: signedMessage, publicKey: keyPair.publicKey)!
        XCTAssertEqual(unsignedMessage, message)
    }

    func testUtils() {
        var dataToZero = [1, 2, 3, 4] as [UInt8]
        sodium.utils.zero(&dataToZero)
        XCTAssert(dataToZero == [0, 0, 0, 0] as [UInt8])

        var dataToZero2 = [1, 2, 3, 4] as [UInt8]
        sodium.utils.zero(&dataToZero2)
        XCTAssert(dataToZero2 == [0, 0, 0, 0,] as [UInt8])

        let eq1 = [1, 2, 3, 4] as [UInt8]
        let eq2 = [1, 2, 3, 4] as [UInt8]
        let eq3 = [1, 2, 3, 5] as [UInt8]
        let eq4 = [1, 2, 3] as [UInt8]

        XCTAssertTrue(sodium.utils.equals(eq1, eq2))
        XCTAssertFalse(sodium.utils.equals(eq1, eq3))
        XCTAssertFalse(sodium.utils.equals(eq1, eq4))

        XCTAssertEqual(sodium.utils.compare(eq1, eq2)!,  0)
        XCTAssertEqual(sodium.utils.compare(eq1, eq3)!, -1)
        XCTAssertEqual(sodium.utils.compare(eq3, eq2)!, 1)
        XCTAssertNil(sodium.utils.compare(eq1, eq4))

        let bin = sodium.utils.hex2bin("deadbeef")!
        let hex = sodium.utils.bin2hex(bin)
        XCTAssertEqual(hex, "deadbeef")
        let bin2 = sodium.utils.hex2bin("de-ad be:ef", ignore: ":- ")!
        XCTAssertEqual(bin2, bin)
    }

    func testPwHash() {
        let passwordLen = 4 + Int(sodium.randomBytes.uniform(upperBound: 64))
        let password = sodium.randomBytes.buf(length: passwordLen)!
        let hash = sodium.pwHash.str(passwd: password, opsLimit: sodium.pwHash.OpsLimitInteractive, memLimit: sodium.pwHash.MemLimitInteractive)
        XCTAssertLessThanOrEqual(hash!.lengthOfBytes(using: String.Encoding.utf8), sodium.pwHash.StrBytes)
        let verify = sodium.pwHash.strVerify(hash: hash!, passwd: password)
        XCTAssertTrue(verify)
        let password2 = sodium.randomBytes.buf(length: passwordLen)!
        let verify2 = sodium.pwHash.strVerify(hash: hash!, passwd: password2)
        XCTAssertFalse(verify2)

        let password3 = "My Test Message".bytes
        let salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] as [UInt8]
        let hash2 = sodium.pwHash.hash(outputLength: 64, passwd: password3, salt: salt, opsLimit: sodium.pwHash.OpsLimitInteractive, memLimit: sodium.pwHash.MemLimitInteractive)
        XCTAssertEqual(sodium.utils.bin2hex(hash2!)!, "cc80dee6a19da46ed6ea11507dd709ce52519ddd1fd2d823ce85b9e9b4fd96d06583de2ca8bcc5998f3483a8a424c4e93ddb500968b0dbefb667d56d421d5a6c")

        XCTAssertFalse(sodium.pwHash.strNeedsRehash(hash: hash!, opsLimit: sodium.pwHash.OpsLimitInteractive, memLimit: sodium.pwHash.MemLimitInteractive))
        XCTAssertTrue(sodium.pwHash.strNeedsRehash(hash: hash!, opsLimit: sodium.pwHash.OpsLimitSensitive, memLimit: sodium.pwHash.MemLimitSensitive))
    }
    
    func testSHA256Hash() {
        let message = "My Test Message".bytes
        let h = sodium.utils.bin2hex(sodium.sha256Hash.hash(message: message)!)!
        XCTAssertEqual(h, "06b87ce47e9cb96156a4f55e405c2587fff2be2ed11adb9f465dc964ef70938e")
    }
    
    func testSHA512Hash() {
        let message = "My Test Message".bytes
        let h = sodium.utils.bin2hex(sodium.sha512Hash.hash(message: message)!)!
        XCTAssertEqual(h, "4173c1218c42b37943f39a7c5a87b782ae945b8609b8dae66a0552c56abd931ba0561a6df052008c1994a505024c31f183a5c34c0dda1e0ce82e9b9e7ea08459")
    }

    func testKeyExchange() {
        let aliceKeyPair = sodium.keyExchange.keyPair()!
        let bobKeyPair = sodium.keyExchange.keyPair()!

        let sessionKeyPairForAlice = sodium.keyExchange.sessionKeyPair(publicKey: aliceKeyPair.publicKey, secretKey: aliceKeyPair.secretKey, otherPublicKey: bobKeyPair.publicKey, side: .CLIENT)!
        let sessionKeyPairForBob = sodium.keyExchange.sessionKeyPair(publicKey: bobKeyPair.publicKey, secretKey: bobKeyPair.secretKey, otherPublicKey: aliceKeyPair.publicKey, side: .SERVER)!

        XCTAssertEqual(sessionKeyPairForAlice.rx, sessionKeyPairForBob.tx)
        XCTAssertEqual(sessionKeyPairForAlice.tx, sessionKeyPairForBob.rx)
    }

    func testStream() {
        let key = sodium.stream.key()
        let inputLen = Int(sodium.randomBytes.uniform(upperBound: 1024))
        let input = sodium.randomBytes.buf(length: inputLen)!
        let (output, nonce) = sodium.stream.xor(input: input, secretKey: key)!
        let twice = sodium.stream.xor(input: output, nonce: nonce, secretKey: key)!

        XCTAssertEqual(input, twice)
    }

    func testAuth() {
        let key = sodium.utils.hex2bin("eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880")!
        let message = sodium.utils.hex2bin("8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5")!
        let tag = sodium.auth.tag(message: message, secretKey: key)!
        XCTAssertEqual(sodium.utils.bin2hex(tag)!, "b2a31b8d4e01afcab2ee545b5caf4e3d212a99d7b3a116a97cec8e83c32e107d")
        let verify = sodium.auth.verify(message: message, secretKey: key, tag: tag)
        XCTAssertTrue(verify)
        let key2 = sodium.auth.key()
        let verify2 = sodium.auth.verify(message: message, secretKey: key2, tag: tag)
        XCTAssertFalse(verify2)
    }

    func testKeyDerivationInputKeyTooShort() {
        let secretKey = sodium.randomBytes.buf(length: sodium.keyDerivation.KeyBytes - 1)!

        XCTAssertNil(sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin, context: "TEST"))
    }

    func testKeyDerivationInputKeyTooLong() {
        let secretKey = sodium.randomBytes.buf(length: sodium.keyDerivation.BytesMax + 1)!
        XCTAssertNil(sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin, context: "TEST"))
    }

    func testKeyDerivationSubKeyTooShort() {
        let secretKey = sodium.keyDerivation.key()
        XCTAssertNil(sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin - 1, context: "TEST"))
    }

    func testKeyDerivationSubKeyTooLong() {
        let secretKey = sodium.keyDerivation.key()
        XCTAssertNil(sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMax + 1, context: "TEST"))
    }

    func testKeyDerivationContextTooLong() {
        let secretKey = sodium.keyDerivation.key()
        XCTAssertNil(sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin, context: "TEST_SODIUM"))
    }

    func testKeyDerivation() {
        let secretKey = sodium.keyDerivation.key()
        let subKey1 = sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin, context: "TEST")!
        let subKey2 = sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin, context: "TEST")!
        let subKey3 = sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin, context: "TEST\0")!
        let subKey4 = sodium.keyDerivation.derive(secretKey: secretKey, index: 1, length: sodium.keyDerivation.BytesMin, context: "TEST")!
        let subKey5 = sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin, context: "test")!

        XCTAssertEqual(subKey1, subKey2, "Equally derived keys must be equal!")
        XCTAssertEqual(subKey1, subKey3, "Manual padding should result in same key.")

        XCTAssertNotEqual(subKey1, subKey4, "Subkeys with different indices must be different!")
        XCTAssertNotEqual(subKey1, subKey5, "Subkeys with different contexts must be different!")
    }

    func testKeyDerivationRegression() {
        let secretKey = sodium.utils.hex2bin("a9029ec4ec56dd6f3ce5a5fa27a17a005ce73a5b8e77529887f24f73ffa10d67")!
        let subKey1 = sodium.keyDerivation.derive(secretKey: secretKey, index: 0, length: sodium.keyDerivation.BytesMin, context: "TEST")!
        let subKey2 = sodium.keyDerivation.derive(secretKey: secretKey, index: 1, length: sodium.keyDerivation.BytesMin, context: "TEST")!

        XCTAssertEqual(sodium.utils.bin2hex(subKey1)!, "40d69c5e6e8b46e399433c9b5c3a7713")
        XCTAssertEqual(sodium.utils.bin2hex(subKey2)!, "8ba83c1cd5a3be912a80ef2abe1457c5")
    }

    func testSecretStream() {
        let secretKey = sodium.secretStream.xchacha20poly1305.key()
        XCTAssertEqual(secretKey.count, 32)

        let stream = sodium.secretStream.xchacha20poly1305.initPush(secretKey: secretKey)!
        let header = stream.header()
        let encrypted1 = stream.push(message: "message 1".bytes)!
        let encrypted2 = stream.push(message: "message 2".bytes)!
        let encrypted3 = stream.push(message: "message 3".bytes, tag: .FINAL)!

        let stream2 = sodium.secretStream.xchacha20poly1305.initPull(secretKey: secretKey, header: header)!
        let (message1, tag1) = stream2.pull(cipherText: encrypted1)!
        let (message2, tag2) = stream2.pull(cipherText: encrypted2)!
        let (message3, tag3) = stream2.pull(cipherText: encrypted3)!
        XCTAssertEqual(tag1, .MESSAGE)
        XCTAssertEqual(tag2, .MESSAGE)
        XCTAssertEqual(tag3, .FINAL)
        XCTAssertEqual(message1, "message 1".bytes)
        XCTAssertEqual(message2, "message 2".bytes)
        XCTAssertEqual(message3, "message 3".bytes)
        XCTAssertNil(stream2.pull(cipherText: encrypted3))
    }

    func testBase64() {
        let bin = "test".bytes
        let b64 = sodium.utils.bin2base64(bin)!
        let bin2 = sodium.utils.base642bin(b64)!
        XCTAssertEqual(b64, "dGVzdA==")
        XCTAssertEqual(bin2, bin)

        let b64_nopad = sodium.utils.bin2base64(bin, variant: .URLSAFE_NO_PADDING)!
        let bin2_nopad = sodium.utils.base642bin(b64_nopad, variant: .URLSAFE_NO_PADDING)!
        XCTAssertEqual(b64_nopad, "dGVzdA")
        XCTAssertEqual(bin2_nopad, bin)
    }

    func testPad() {
        var data = "test".bytes
        sodium.utils.pad(bytes: &data, blockSize: 16)!
        XCTAssertTrue(data.count % 16 == 0)
        sodium.utils.unpad(bytes: &data, blockSize: 16)!
        XCTAssertTrue(data.count == 4)
    }
    
    func testAead() {
        let message = " I am message".bytes
        let additionalData = "I am additionalData".bytes
        
        let secretKey = sodium.aead.xchacha20poly1305ietf.key()
        XCTAssertEqual(secretKey.count, 32)
        
        let (authenticatedCipherText, nonce) = sodium.aead.xchacha20poly1305ietf.encrypt(message: message, secretKey: secretKey)!
        
        XCTAssertEqual(nonce.count, 24) // check nonce is 192 bit
        
        let decrypted: Bytes = sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: secretKey, nonce: nonce)!
        
        XCTAssertTrue(decrypted == message)
        
        let (authenticatedCipherTextWithAdditionalData, nonceWithAdditionlData) = sodium.aead.xchacha20poly1305ietf.encrypt(message: message, secretKey: secretKey, additionalData: additionalData)!
        let decrypted2: Bytes = sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: authenticatedCipherTextWithAdditionalData, secretKey: secretKey, nonce: nonceWithAdditionlData, additionalData: additionalData)!
        
        XCTAssertTrue(decrypted2 == message)
        
        XCTAssertNil(sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: secretKey, nonce: nonceWithAdditionlData, additionalData: additionalData), "Decrypt using additionalData but encrypted without")
        XCTAssertNil(sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: authenticatedCipherTextWithAdditionalData, secretKey: secretKey, nonce: nonceWithAdditionlData), "Decrypt without additionalData but encrypted with additionalData")
        
        XCTAssertNil(sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: sodium.aead.xchacha20poly1305ietf.key(), nonce: nonce), "Decrypt with different key")

        XCTAssertNil(sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: authenticatedCipherTextWithAdditionalData, secretKey: secretKey, nonce: nonceWithAdditionlData, additionalData: "wrong".bytes), "Decrypt with wrong additional data")
        XCTAssertNil(sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: "wrong".bytes, secretKey: secretKey, nonce: nonce))

        XCTAssertNil(sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: secretKey, nonce: "invalid".bytes))
        XCTAssertNil(sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: "invalid".bytes, nonce: nonce))
        
        let nonceAndAuthenticatedCipherText: Bytes = sodium.aead.xchacha20poly1305ietf.encrypt(message: message, secretKey: secretKey)!
        let decrypted3: Bytes = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: nonceAndAuthenticatedCipherText, secretKey: secretKey)!
        
        XCTAssertTrue(decrypted3 == message)
        
        let nonceAndAuthenticatedCipherTextWithAddData: Bytes = sodium.aead.xchacha20poly1305ietf.encrypt(message: message, secretKey: secretKey, additionalData: additionalData)!
        let decrypted4: Bytes = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: nonceAndAuthenticatedCipherTextWithAddData, secretKey: secretKey, additionalData: additionalData)!
        
        XCTAssertTrue(decrypted4 == message)
        
        // encrypt -> decrypt empty message
        let emptyMessage = "".bytes
        let encryptedEmpty: Bytes = sodium.aead.xchacha20poly1305ietf.encrypt(message: emptyMessage, secretKey: secretKey, additionalData: additionalData)!
        let decryptedEmpty: Bytes = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: encryptedEmpty, secretKey: secretKey, additionalData: additionalData)!
        
        XCTAssertTrue(decryptedEmpty == emptyMessage)
    }

    func testRFC8032Vector1() {
        // test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
        let message = sodium.utils.hex2bin("")!
        let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        let expectedPublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        let expectedSignature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

        let keyPair = sodium.sign.keyPair(seed: sodium.utils.hex2bin(seed)!)!

        XCTAssertEqual(sodium.utils.bin2hex(keyPair.publicKey)!, expectedPublicKey)

        let signature = sodium.sign.signature(message: message, secretKey: keyPair.secretKey)!
        XCTAssertEqual(sodium.utils.bin2hex(signature)!, expectedSignature)
        XCTAssertTrue(sodium.sign.verify(message: message, publicKey: keyPair.publicKey, signature: signature))
    }

    func testRFC8032Vector2() {
        // test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
        let message = sodium.utils.hex2bin("72")!
        let seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        let expectedPublicKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        let expectedSignature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"

        let keyPair = sodium.sign.keyPair(seed: sodium.utils.hex2bin(seed)!)!

        XCTAssertEqual(sodium.utils.bin2hex(keyPair.publicKey)!, expectedPublicKey)

        let signature = sodium.sign.signature(message: message, secretKey: keyPair.secretKey)!
        XCTAssertEqual(sodium.utils.bin2hex(signature)!, expectedSignature)
        XCTAssertTrue(sodium.sign.verify(message: message, publicKey: keyPair.publicKey, signature: signature))
    }

    func testRFC8032Vector3() {
        // test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
        let message = sodium.utils.hex2bin("af82")!
        let seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
        let expectedPublicKey = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        let expectedSignature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"

        let keyPair = sodium.sign.keyPair(seed: sodium.utils.hex2bin(seed)!)!

        XCTAssertEqual(sodium.utils.bin2hex(keyPair.publicKey)!, expectedPublicKey)

        let signature = sodium.sign.signature(message: message, secretKey: keyPair.secretKey)!
        XCTAssertEqual(sodium.utils.bin2hex(signature)!, expectedSignature)
        XCTAssertTrue(sodium.sign.verify(message: message, publicKey: keyPair.publicKey, signature: signature))
    }

    func testRFC8032Vector1024() {
        // test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
        let message = sodium.utils.hex2bin("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0")!
        let seed = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
        let expectedPublicKey = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
        let expectedSignature = "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"

        let keyPair = sodium.sign.keyPair(seed: sodium.utils.hex2bin(seed)!)!

        XCTAssertEqual(sodium.utils.bin2hex(keyPair.publicKey)!, expectedPublicKey)

        let signature = sodium.sign.signature(message: message, secretKey: keyPair.secretKey)!
        XCTAssertEqual(sodium.utils.bin2hex(signature)!, expectedSignature)
        XCTAssertTrue(sodium.sign.verify(message: message, publicKey: keyPair.publicKey, signature: signature))
    }

    func testRFC8032VectorSHAABC() {
        // test vectors from https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
        let message = sodium.utils.hex2bin("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")!
        let seed = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
        let expectedPublicKey = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
        let expectedSignature = "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"

        let keyPair = sodium.sign.keyPair(seed: sodium.utils.hex2bin(seed)!)!

        XCTAssertEqual(sodium.utils.bin2hex(keyPair.publicKey)!, expectedPublicKey)

        let signature = sodium.sign.signature(message: message, secretKey: keyPair.secretKey)!
        XCTAssertEqual(sodium.utils.bin2hex(signature)!, expectedSignature)
        XCTAssertTrue(sodium.sign.verify(message: message, publicKey: keyPair.publicKey, signature: signature))
    }
}
