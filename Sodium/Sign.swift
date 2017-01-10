//
//  Sign.swift
//  Sodium
//
//  Created by Frank Denis on 12/28/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class Sign {
    public let SeedBytes = Int(crypto_sign_seedbytes())
    public let PublicKeyBytes = Int(crypto_sign_publickeybytes())
    public let SecretKeyBytes = Int(crypto_sign_secretkeybytes())
    public let Bytes = Int(crypto_sign_bytes())
    public let Primitive = String(validatingUTF8: crypto_sign_primitive())

    public typealias PublicKey = Data
    public typealias SecretKey = Data

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
                return crypto_sign_keypair(pkPtr, skPtr)
            }
        }

        if result != 0 {
            return nil
        }

        return KeyPair(publicKey: pk,
                       secretKey: sk)
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
                    return crypto_sign_seed_keypair(pkPtr, skPtr, seedPtr)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return KeyPair(publicKey: pk,
                       secretKey: sk)
    }

    public func sign(message: Data, secretKey: SecretKey) -> Data? {
        if secretKey.count != SecretKeyBytes {
            return nil
        }

        var signedMessage = Data(count: message.count + Bytes)
        let result = signedMessage.withUnsafeMutableBytes { signedMessagePtr in
            return message.withUnsafeBytes { messagePtr in
                return secretKey.withUnsafeBytes { secretKeyPtr in
                    return crypto_sign(
                      signedMessagePtr,
                      nil,
                      messagePtr,
                      CUnsignedLongLong(message.count),
                      secretKeyPtr)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return signedMessage
    }

    public func signature(message: Data, secretKey: SecretKey) -> Data? {
        if secretKey.count != SecretKeyBytes {
            return nil
        }

        var signature = Data(count: Bytes)
        let result = signature.withUnsafeMutableBytes { signaturePtr in
            return message.withUnsafeBytes { messagePtr in
                return secretKey.withUnsafeBytes { secretKeyPtr in
                    return crypto_sign_detached(
                      signaturePtr,
                      nil,
                      messagePtr,
                      CUnsignedLongLong(message.count),
                      secretKeyPtr)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return signature
    }

    public func verify(signedMessage: Data, publicKey: PublicKey) -> Bool {
        let signature = signedMessage.subdata(in: 0..<Bytes) as Data
        let message = signedMessage.subdata(in: Bytes..<signedMessage.count) as Data
        return verify(message: message, publicKey: publicKey, signature: signature)
    }

    public func verify(message: Data, publicKey: PublicKey, signature: Data) -> Bool {
        if publicKey.count != PublicKeyBytes {
            return false
        }

        return signature.withUnsafeBytes { signaturePtr in
            return message.withUnsafeBytes { messagePtr in
                return publicKey.withUnsafeBytes { publicKeyPtr in
                    return crypto_sign_verify_detached(
                      signaturePtr,
                      messagePtr,
                      CUnsignedLongLong(message.count), publicKeyPtr) == 0
                }
            }
        }
    }

    public func open(signedMessage: Data, publicKey: PublicKey) -> Data? {
        if publicKey.count != PublicKeyBytes || signedMessage.count < Bytes {
            return nil
        }

        var message = Data(count: signedMessage.count - Bytes)
        var mlen: CUnsignedLongLong = 0;
        let result = message.withUnsafeMutableBytes { messagePtr in
            return signedMessage.withUnsafeBytes { signedMessagePtr in
                return publicKey.withUnsafeBytes { publicKeyPtr in
                    return crypto_sign_open(messagePtr, &mlen, signedMessagePtr, CUnsignedLongLong(signedMessage.count), publicKeyPtr)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return message
    }
}
