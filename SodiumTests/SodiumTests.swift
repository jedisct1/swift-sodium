//
//  SodiumTests.swift
//  SodiumTests
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import XCTest
import Sodium

extension String {
    func toData() -> NSData? {
        return self.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
    }
}

extension NSData {
    func toString() -> String? {
        return (NSString(data: self, encoding: NSUTF8StringEncoding) as! String)
    }
}

class SodiumTests: XCTestCase {
    let sodium = Sodium(())!

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testBox() {
        let message = "My Test Message".toData()!
        let aliceKeyPair = sodium.box.keyPair()!
        let bobKeyPair = sodium.box.keyPair()!

        let encryptedMessageFromAliceToBob: NSData = sodium.box.seal(message, recipientPublicKey: bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey)!
        let decrypted = sodium.box.open(encryptedMessageFromAliceToBob, senderPublicKey: bobKeyPair.publicKey, recipientSecretKey: aliceKeyPair.secretKey)
        XCTAssert(decrypted == message)

        let (encryptedMessageFromAliceToBob2, nonce): (NSData, Box.Nonce) = sodium.box.seal(message, recipientPublicKey: bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey)!
        let decrypted2 = sodium.box.open(encryptedMessageFromAliceToBob2, senderPublicKey: aliceKeyPair.publicKey, recipientSecretKey: bobKeyPair.secretKey, nonce: nonce)
        XCTAssert(decrypted2 == message)

        let (encryptedMessageFromAliceToBob3, nonce2, mac): (NSData, Box.Nonce, Box.MAC) = sodium.box.seal(message, recipientPublicKey: bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey)!
        let decrypted3 = sodium.box.open(encryptedMessageFromAliceToBob3, senderPublicKey: aliceKeyPair.publicKey, recipientSecretKey: bobKeyPair.secretKey, nonce: nonce2, mac: mac)
        XCTAssert(decrypted3 == message)

        let encryptedMessageToBob: NSData = sodium.box.seal(message, recipientPublicKey: bobKeyPair.publicKey)!
        let decrypted4 = sodium.box.open(encryptedMessageToBob, recipientPublicKey: bobKeyPair.publicKey,
            recipientSecretKey: bobKeyPair.secretKey)
        XCTAssert(decrypted4 == message)

        // beforenm tests
        // The two beforenm keys calculated by Alice and Bob separately should be identical
        let aliceBeforenm = sodium.box.beforenm(bobKeyPair.publicKey, senderSecretKey: aliceKeyPair.secretKey)!
        let bobBeforenm = sodium.box.beforenm(aliceKeyPair.publicKey, senderSecretKey: bobKeyPair.secretKey)!
        XCTAssert(aliceBeforenm == bobBeforenm)

        // Make sure the encryption using beforenm works
        let encryptedMessageBeforenm: NSData = sodium.box.seal(message, beforenm: aliceBeforenm)!
        let decryptedBeforenm = sodium.box.open(encryptedMessageBeforenm, beforenm: aliceBeforenm)
        XCTAssert(decryptedBeforenm == message)

        let (encryptedMessageBeforenm2, nonceBeforenm): (NSData, Box.Nonce) = sodium.box.seal(message, beforenm: aliceBeforenm)!
        let decryptedBeforenm2 = sodium.box.open(encryptedMessageBeforenm2, beforenm: aliceBeforenm, nonce: nonceBeforenm)
        XCTAssert(decryptedBeforenm2 == message)
    }

    func testSecretBox() {
        let message = "My Test Message".toData()!
        let secretKey = sodium.secretBox.key()!

        // test simple nonce + mac + message box
        let encrypted: NSData = sodium.secretBox.seal(message, secretKey: secretKey)!
        let decrypted = sodium.secretBox.open(encrypted, secretKey: secretKey)!
        XCTAssert(decrypted == message)

        XCTAssertNil(sodium.secretBox.open(encrypted, secretKey: sodium.secretBox.key()!), "Shouldn't be able to decrypt with a bad key")

        // test (mac + message, nonce) box
        let (encrypted2, nonce2) = sodium.secretBox.seal(message, secretKey: secretKey)!
        let decrypted2 = sodium.secretBox.open(encrypted2, secretKey: secretKey, nonce: nonce2)
        XCTAssert(decrypted2 == message)

        XCTAssertNil(sodium.secretBox.open(encrypted2, secretKey: secretKey, nonce: sodium.secretBox.nonce()!), "Shouldn't be able to decrypt with an invalid nonce")

        // test (message, nonce, mac) box
        let (encrypted3, nonce3, mac3) = sodium.secretBox.seal(message, secretKey: secretKey)!
        let decrypted3 = sodium.secretBox.open(encrypted3, secretKey: secretKey, nonce: nonce3, mac: mac3)
        XCTAssert(decrypted3 == message)

        let (encrypted4, nonce4, mac4) = sodium.secretBox.seal(message, secretKey: secretKey)!
        XCTAssertNil(sodium.secretBox.open(encrypted4, secretKey: secretKey, nonce: nonce3, mac: mac4), "Shouldn't be able to decrypt with an invalid MAC")
        XCTAssertNil(sodium.secretBox.open(encrypted4, secretKey: secretKey, nonce: nonce4, mac: mac3), "Shouldn't be able to decrypt with an invalid nonce")
    }

    func testGenericHash() {
        let message = "My Test Message".toData()!
        let h1 = sodium.utils.bin2hex(sodium.genericHash.hash(message)!)!
        XCTAssert(h1 == "64a9026fca646c31df54426ad15a341e2444d8a1863d57eb27abecf239609f75")

        let key = sodium.utils.hex2bin("64 a9 02 6f ca 64 6c 31 df 54", ignore: " ")
        let h2 = sodium.utils.bin2hex(sodium.genericHash.hash(message, key: key)!)!
        XCTAssert(h2 == "1773f324cba2e7b0017e32d7e44f7afd1036c5d4ef9a80ae0e52e95a629844cd")

        let h3 = sodium.utils.bin2hex(sodium.genericHash.hash(message, key: key, outputLength: sodium.genericHash.BytesMax)!)!
        XCTAssert(h3 == "cba85e39f2d03923b2f66aba99b204333edc34a8443ab1700f7920c7abcc6639963a953f35162a520b21072ab906457d21f1645e6e3985858ee95a84d0771f07")

        let s1 = sodium.genericHash.initStream()!
        s1.update(message)
        let h4 = sodium.utils.bin2hex(s1.final()!)!
        XCTAssert(h4 == h1)

        let s2 = sodium.genericHash.initStream(key, outputLength: sodium.genericHash.Bytes)!
        s2.update(message)
        let h5 = sodium.utils.bin2hex(s2.final()!)!
        XCTAssert(h5 == h2)

        let s3 = sodium.genericHash.initStream(key, outputLength: sodium.genericHash.BytesMax)!
        s3.update(message)
        let h6 = sodium.utils.bin2hex(s3.final()!)!
        XCTAssert(h6 == h3)
    }

    func testRandomBytes() {
        let randomLen = 100 + Int(sodium.randomBytes.uniform(100))
        let random1 = sodium.randomBytes.buf(randomLen)!
        let random2 = sodium.randomBytes.buf(randomLen)!
        XCTAssert(random1.length == randomLen)
        XCTAssert(random2.length == randomLen)
        XCTAssert(random1 != random2)

        var c1 = 0
        let ref1 = self.sodium.randomBytes.random()
        for _ in (0..<100) {
            if sodium.randomBytes.random() == ref1 {
                c1 += 1
            }
        }
        XCTAssert(c1 < 10)

        var c2 = 0
        let ref2 = self.sodium.randomBytes.uniform(100_000)
        for _ in (0..<100) {
            if sodium.randomBytes.uniform(100_000) == ref2 {
                c2 += 1
            }
        }
        XCTAssert(c2 < 10)
    }

    func testShortHash() {
        let message = "My Test Message".toData()!
        let key = sodium.utils.hex2bin("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff", ignore: " ")!
        let h = sodium.utils.bin2hex(sodium.shortHash.hash(message, key: key)!)!
        XCTAssert(h == "bb9be85c918015ea")
    }

    func testSignature() {
        let message = "My Test Message".toData()!
        let keyPair = sodium.sign.keyPair(seed: sodium.utils.hex2bin("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff", ignore: " ")!)!
        let signedMessage = sodium.sign.sign(message, secretKey: keyPair.secretKey)!
        XCTAssert(sodium.utils.bin2hex(signedMessage)! == "ce8437d58a27c4d91426d35b24cfaf1e49f95b213c15eddb198f4a8d24c0fdd0df3e7f7a894f60ec15cff25b5f6f27399ce01db0e2649fc54c91cafb8dd48a094d792054657374204d657373616765")

        let signature = sodium.sign.signature(message, secretKey: keyPair.secretKey)!
        XCTAssert(sodium.utils.bin2hex(signature)! == "ce8437d58a27c4d91426d35b24cfaf1e49f95b213c15eddb198f4a8d24c0fdd0df3e7f7a894f60ec15cff25b5f6f27399ce01db0e2649fc54c91cafb8dd48a09")

        XCTAssert(sodium.sign.verify(signedMessage, publicKey: keyPair.publicKey) == true)
        XCTAssert(sodium.sign.verify(message, publicKey: keyPair.publicKey, signature: signature) == true)

        let unsignedMessage = sodium.sign.open(signedMessage, publicKey: keyPair.publicKey)!
        XCTAssert(unsignedMessage == message)
    }

    func testUtils() {
        let dataToZero = NSMutableData(bytes: [1, 2, 3, 4] as [UInt8], length: 4)
        sodium.utils.zero(dataToZero)
        XCTAssert(dataToZero.length == 0)

        let eq1 = NSData(bytes: [1, 2, 3, 4] as [UInt8], length: 4)
        let eq2 = NSData(bytes: [1, 2, 3, 4] as [UInt8], length: 4)
        let eq3 = NSData(bytes: [1, 2, 3, 5] as [UInt8], length: 4)
        let eq4 = NSData(bytes: [1, 2, 3] as [UInt8], length: 3)
        XCTAssert(sodium.utils.equals(eq1, eq2))
        XCTAssert(!sodium.utils.equals(eq1, eq3))
        XCTAssert(!sodium.utils.equals(eq1, eq4))

        XCTAssert(sodium.utils.compare(eq1, eq2)! == 0)
        XCTAssert(sodium.utils.compare(eq1, eq3)! == -1)
        XCTAssert(sodium.utils.compare(eq3, eq2)! == 1)
        XCTAssert(sodium.utils.compare(eq1, eq4) == nil)

        let bin = sodium.utils.hex2bin("deadbeef")!
        XCTAssert(bin.description == "<deadbeef>")
        let hex = sodium.utils.bin2hex(bin)
        XCTAssert(hex == "deadbeef")
        let bin2 = sodium.utils.hex2bin("de-ad be:ef", ignore: ":- ")!
        XCTAssert(bin2 == bin)
    }

    func testScrypt() {
        let passwordLen = Int(sodium.randomBytes.uniform(64))
        let password = sodium.randomBytes.buf(passwordLen)!
        let hash = sodium.pwHash.scrypt.str(password, opsLimit: sodium.pwHash.scrypt.OpsLimitInteractive, memLimit: sodium.pwHash.scrypt.MemLimitInteractive)
        XCTAssert(hash?.lengthOfBytesUsingEncoding(NSUTF8StringEncoding) == sodium.pwHash.scrypt.StrBytes)
        let verify = sodium.pwHash.scrypt.strVerify(hash!, passwd: password)
        XCTAssert(verify == true)
        let password2 = sodium.randomBytes.buf(passwordLen)!
        let verify2 = sodium.pwHash.scrypt.strVerify(hash!, passwd: password2)
        XCTAssert(verify2 == false)

        let password3 = "My Test Message".toData()!
        let salt = NSData(bytes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32] as [UInt8], length: 32)
        let hash2 = sodium.pwHash.scrypt.hash(64, passwd: password3, salt: salt, opsLimit: sodium.pwHash.scrypt.OpsLimitInteractive, memLimit: sodium.pwHash.scrypt.MemLimitInteractive)
        NSLog(sodium.utils.bin2hex(hash2!)!)
        XCTAssert(sodium.utils.bin2hex(hash2!)! == "6f00c5630b0a113be73721d2bab7800c0fce4b4e7a74451704b53afcded3d9e85fbe1acea7d2aa0fecb3027e35d745547b1041d6c51f731bd0aa934da89f7adf")
    }

    func testPwHash() {
        let passwordLen = Int(sodium.randomBytes.uniform(64))
        let password = sodium.randomBytes.buf(passwordLen)!
        let hash = sodium.pwHash.str(password, opsLimit: sodium.pwHash.OpsLimitInteractive, memLimit: sodium.pwHash.MemLimitInteractive)
        XCTAssert(hash?.lengthOfBytesUsingEncoding(NSUTF8StringEncoding) == sodium.pwHash.StrBytes)
        let verify = sodium.pwHash.strVerify(hash!, passwd: password)
        XCTAssert(verify == true)
        let password2 = sodium.randomBytes.buf(passwordLen)!
        let verify2 = sodium.pwHash.strVerify(hash!, passwd: password2)
        XCTAssert(verify2 == false)

        let password3 = "My Test Message".toData()!
        let salt = NSData(bytes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] as [UInt8], length: 16)
        let hash2 = sodium.pwHash.hash(64, passwd: password3, salt: salt, opsLimit: sodium.pwHash.OpsLimitInteractive, memLimit: sodium.pwHash.MemLimitInteractive)
        XCTAssert(sodium.utils.bin2hex(hash2!)! == "51d659ee6f8790042688274c5bc8a6296390cdc786d2341c3553b01a5c3f7ff1190e04b86a878538b17ef10e74baa19295479f3e3ee587ce571f366fc66e2fdc")
    }
}
