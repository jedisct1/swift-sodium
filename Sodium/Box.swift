//
//  Box.swift
//  Sodium
//
//  Created by Frank Denis on 12/28/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class Box {
    public let SeedBytes = Int(crypto_box_seedbytes())
    public let PublicKeyBytes = Int(crypto_box_publickeybytes())
    public let SecretKeyBytes = Int(crypto_box_secretkeybytes())
    public let NonceBytes = Int(crypto_box_noncebytes())
    public let MacBytes = Int(crypto_box_macbytes())
    public let Primitive = String.init(validatingUTF8:crypto_box_primitive())
    public let BeforenmBytes = Int(crypto_box_beforenmbytes())
    public let SealBytes = Int(crypto_box_sealbytes())

    public typealias PublicKey = Data
    public typealias SecretKey = Data
    public typealias Nonce = Data
    public typealias MAC = Data
    public typealias Beforenm = Data

    public struct KeyPair {
        public let publicKey: PublicKey
        public let secretKey: SecretKey

        public init(publicKey: PublicKey, secretKey: SecretKey) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }

    public func keyPair() -> KeyPair? {
        var pk = Data(count: PublicKeyBytes)
        var sk = Data(count: SecretKeyBytes)
        let result = pk.withUnsafeMutableBytes { pkPtr in
            return sk.withUnsafeMutableBytes { skPtr in
                return crypto_box_keypair(pkPtr, skPtr)
            }
        }

        if result != 0 {
            return nil
        }

        return KeyPair(publicKey: pk, secretKey: sk)
    }

    public func keyPair(seed: Data) -> KeyPair? {
        if seed.count != SeedBytes {
            return nil
        }

        var pk = Data(count: PublicKeyBytes)
        var sk = Data(count: SecretKeyBytes)

        let result = pk.withUnsafeMutableBytes { pkPtr in
            return sk.withUnsafeMutableBytes { skPtr in
                return seed.withUnsafeBytes { seedPtr in
                    return crypto_box_seed_keypair(pkPtr, skPtr, seedPtr)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return KeyPair(publicKey: pk, secretKey: sk)
    }

    public func nonce() -> Nonce {
        var nonce = Data(count: NonceBytes)
        nonce.withUnsafeMutableBytes { noncePtr in
            randombytes_buf(noncePtr, nonce.count)
        }
        return nonce
    }

    public func seal(message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> Data? {
        guard let (authenticatedCipherText, nonce): (Data, Nonce) = seal(message: message, recipientPublicKey: recipientPublicKey, senderSecretKey: senderSecretKey) else {
            return nil
        }
        var nonceAndAuthenticatedCipherText = nonce
        nonceAndAuthenticatedCipherText.append(authenticatedCipherText)
        return nonceAndAuthenticatedCipherText
    }

    public func seal(message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: Data, nonce: Nonce)? {
        if recipientPublicKey.count != PublicKeyBytes || senderSecretKey.count != SecretKeyBytes {
            return nil
        }
        var authenticatedCipherText = Data(count: message.count + MacBytes)
        let nonce = self.nonce()

        let result = authenticatedCipherText.withUnsafeMutableBytes { authenticatedCipherTextPtr in
            return message.withUnsafeBytes { messagePtr in
                return nonce.withUnsafeBytes { noncePtr in
                    return recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                        return senderSecretKey.withUnsafeBytes { senderSecretKeyPtr in
                            return crypto_box_easy(
                              authenticatedCipherTextPtr,
                              messagePtr,
                              CUnsignedLongLong(message.count),
                              noncePtr,
                              recipientPublicKeyPtr,
                              senderSecretKeyPtr)
                        }
                    }
                }
            }
        }

        if result != 0 {
            return nil
        }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    public func seal(message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: Data, nonce: Nonce, mac: MAC)? {
        if recipientPublicKey.count != PublicKeyBytes || senderSecretKey.count != SecretKeyBytes {
            return nil
        }
        var authenticatedCipherText = Data(count: message.count)
        var mac = Data(count: MacBytes)
        let nonce = self.nonce()
        let result =  authenticatedCipherText.withUnsafeMutableBytes { authenticatedCipherTextPtr in
            return mac.withUnsafeMutableBytes { macPtr in
                return message.withUnsafeBytes { messagePtr in
                    return nonce.withUnsafeBytes { noncePtr in
                        return recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                            return senderSecretKey.withUnsafeBytes { senderSecretKeyPtr in
                                return crypto_box_detached(
                                  authenticatedCipherTextPtr,
                                  macPtr,
                                  messagePtr,
                                  CUnsignedLongLong(message.count),
                                  noncePtr,
                                  recipientPublicKeyPtr,
                                  senderSecretKeyPtr)
                            }
                        }
                    }
                }
            }
        }

        if result != 0 {
            return nil
        }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce as Nonce, mac: mac as MAC)
    }

    public func open(nonceAndAuthenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey) -> Data? {
        if nonceAndAuthenticatedCipherText.count < NonceBytes + MacBytes {
            return nil
        }
        let nonce = nonceAndAuthenticatedCipherText.subdata(in: 0..<NonceBytes) as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdata(in: NonceBytes..<nonceAndAuthenticatedCipherText.count)
        return open(authenticatedCipherText: authenticatedCipherText, senderPublicKey: senderPublicKey, recipientSecretKey: recipientSecretKey, nonce: nonce)
    }

    public func open(authenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce) -> Data? {
        if nonce.count != NonceBytes || authenticatedCipherText.count < MacBytes {
            return nil
        }

        if senderPublicKey.count != PublicKeyBytes || recipientSecretKey.count != SecretKeyBytes {
            return nil
        }

        var message = Data(count: authenticatedCipherText.count - MacBytes)
        let result = message.withUnsafeMutableBytes { messagePtr in
            return authenticatedCipherText.withUnsafeBytes { authenticatedCipherTextPtr in
                return nonce.withUnsafeBytes { noncePtr in
                    return senderPublicKey.withUnsafeBytes { senderPublicKeyPtr in
                        return recipientSecretKey.withUnsafeBytes { recipientSecretKeyPtr in
                            return crypto_box_open_easy(
                              messagePtr,
                              authenticatedCipherTextPtr,
                              CUnsignedLongLong(authenticatedCipherText.count),
                              noncePtr,
                              senderPublicKeyPtr,
                              recipientSecretKeyPtr)
                        }
                    }
                }
            }
        }

        if result != 0 {
            return nil
        }

        return message
    }

    public func open(authenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce, mac: MAC) -> Data? {
        if nonce.count != NonceBytes || mac.count != MacBytes {
            return nil
        }
        if senderPublicKey.count != PublicKeyBytes || recipientSecretKey.count != SecretKeyBytes {
            return nil
        }
        var message = Data(count: authenticatedCipherText.count)

        let result = message.withUnsafeMutableBytes { messagePtr in
            return authenticatedCipherText.withUnsafeBytes { authenticatedCipherTextPtr in
                return mac.withUnsafeBytes { macPtr in
                    return nonce.withUnsafeBytes { noncePtr in
                        return senderPublicKey.withUnsafeBytes { senderPublicKeyPtr in
                            return recipientSecretKey.withUnsafeBytes { recipientSecretKeyPtr in
                                return crypto_box_open_detached(
                                  messagePtr,
                                  authenticatedCipherTextPtr,
                                  macPtr,
                                  CUnsignedLongLong(authenticatedCipherText.count),
                                  noncePtr,
                                  senderPublicKeyPtr,
                                  recipientSecretKeyPtr)
                            }
                        }
                    }
                }
            }
        }

        if result != 0 {
            return nil
        }

        return message
    }

    public func beforenm(recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> Data? {
        var key = Data(count: BeforenmBytes)
        let result = key.withUnsafeMutableBytes { keyPtr in
            return recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                return senderSecretKey.withUnsafeBytes { senderSecretKeyPtr in
                    return crypto_box_beforenm(keyPtr, recipientPublicKeyPtr, senderSecretKeyPtr)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return key
    }

    public func seal(message: Data, beforenm: Beforenm) -> (authenticatedCipherText: Data, nonce: Nonce)? {
        if beforenm.count != BeforenmBytes {
            return nil
        }

        var authenticatedCipherText = Data(count: message.count + MacBytes)
        let nonce = self.nonce()

        let result = authenticatedCipherText.withUnsafeMutableBytes { authenticatedCipherTextPtr in
            return message.withUnsafeBytes { messagePtr in
                return nonce.withUnsafeBytes { noncePtr in
                    return beforenm.withUnsafeBytes { beforenmPtr in
                        return crypto_box_easy_afternm(
                          authenticatedCipherTextPtr,
                          messagePtr,
                          CUnsignedLongLong(message.count),
                          noncePtr,
                          beforenmPtr)
                    }
                }
            }
        }

        if result != 0 {
            return nil
        }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    public func open(nonceAndAuthenticatedCipherText: Data, beforenm: Beforenm) -> Data? {
        if nonceAndAuthenticatedCipherText.count < NonceBytes + MacBytes {
            return nil
        }

        let nonce = nonceAndAuthenticatedCipherText.subdata(in: 0..<NonceBytes) as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdata(in: NonceBytes..<nonceAndAuthenticatedCipherText.count)
        return  open(authenticatedCipherText: authenticatedCipherText, beforenm: beforenm, nonce: nonce)
    }

    public func open(authenticatedCipherText: Data, beforenm: Beforenm, nonce: Nonce) -> Data? {
        if nonce.count != NonceBytes || authenticatedCipherText.count < MacBytes {
            return nil
        }

        if beforenm.count != BeforenmBytes {
            return nil
        }

        var message = Data(count: authenticatedCipherText.count - MacBytes)
        let result = message.withUnsafeMutableBytes { messagePtr in
            return authenticatedCipherText.withUnsafeBytes { authenticatedCipherTextPtr in
                return nonce.withUnsafeBytes { noncePtr in
                    return beforenm.withUnsafeBytes { beforenmPtr in
                        return crypto_box_open_easy_afternm(
                          messagePtr,
                          authenticatedCipherTextPtr,
                          CUnsignedLongLong(authenticatedCipherText.count),
                          noncePtr,
                          beforenmPtr)
                    }
                }
            }
        }

        if result != 0 {
            return nil
        }

        return message
    }

    public func seal(message: Data, beforenm: Beforenm) -> Data? {
        guard let (authenticatedCipherText, nonce): (Data, Nonce) = seal(message: message, beforenm: beforenm) else {
            return nil
        }

        var nonceAndAuthenticatedCipherText = nonce
        nonceAndAuthenticatedCipherText.append(authenticatedCipherText)
        return nonceAndAuthenticatedCipherText
    }

    public func seal(message: Data, recipientPublicKey: Box.PublicKey) -> Data? {
        if recipientPublicKey.count != PublicKeyBytes {
            return nil
        }

        var anonymousCipherText = Data(count: SealBytes + message.count)
        let result = anonymousCipherText.withUnsafeMutableBytes { anonymousCipherTextPtr in
            return message.withUnsafeBytes { messagePtr in
                return recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                    return crypto_box_seal(
                      anonymousCipherTextPtr,
                      messagePtr,
                      CUnsignedLongLong(message.count),
                      recipientPublicKeyPtr)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return anonymousCipherText
    }

    public func open(anonymousCipherText: Data, recipientPublicKey: PublicKey, recipientSecretKey: SecretKey) -> Data? {
        if recipientPublicKey.count != PublicKeyBytes || recipientSecretKey.count != SecretKeyBytes || anonymousCipherText.count < SealBytes {
            return nil
        }

        var message = Data(count: anonymousCipherText.count - SealBytes)
        let result = message.withUnsafeMutableBytes { messagePtr in
            return anonymousCipherText.withUnsafeBytes { anonymousCipherTextPtr in
                return recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                    return recipientSecretKey.withUnsafeBytes { recipientSecretKeyPtr in
                        return crypto_box_seal_open(
                          messagePtr,
                          anonymousCipherTextPtr,
                          CUnsignedLongLong(anonymousCipherText.count),
                          recipientPublicKeyPtr,
                          recipientSecretKeyPtr)
                    }
                }
            }
        }

        if result != 0 {
            return nil
        }

        return message
    }
}
