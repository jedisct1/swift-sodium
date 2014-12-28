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
    public let Primitive = String.fromCString(crypto_box_primitive())
    
    public typealias PublicKey = NSData
    public typealias SecretKey = NSData
    public typealias Nonce = NSData
    public typealias MAC = NSData
    
    public struct KeyPair {
        public let publicKey: PublicKey
        public let secretKey: SecretKey
    }
    
    public func keyPair() -> KeyPair? {
        let pk = NSMutableData(length: PublicKeyBytes)
        if pk == nil {
            return nil
        }
        let sk = NSMutableData(length: SecretKeyBytes)
        if sk == nil {
            return nil
        }
        if (crypto_box_keypair(UnsafeMutablePointer<UInt8>(pk!.mutableBytes), UnsafeMutablePointer<UInt8>(sk!.mutableBytes)) != 0) {
            return nil
        }
        return KeyPair(publicKey: PublicKey(data: pk!), secretKey: SecretKey(data: sk!))
    }
    
    public func keyPair(seed: NSData) -> KeyPair? {
        if seed.length != SeedBytes {
            return nil
        }
        let pk = NSMutableData(length: PublicKeyBytes)
        if pk == nil {
            return nil
        }
        let sk = NSMutableData(length: SecretKeyBytes)
        if sk == nil {
            return nil
        }
        if (crypto_box_seed_keypair(UnsafeMutablePointer<UInt8>(pk!.mutableBytes), UnsafeMutablePointer<UInt8>(sk!.mutableBytes), UnsafePointer<UInt8>(seed.bytes)) != 0) {
            return nil
        }
        return KeyPair(publicKey: PublicKey(data: pk!), secretKey: SecretKey(data: sk!))
    }
    
    public func nonce() -> Nonce? {
        let nonce = NSMutableData(length: NonceBytes)
        if nonce == nil {
            return nil
        }
        randombytes_buf(UnsafeMutablePointer<UInt8>(nonce!.mutableBytes), UInt(nonce!.length))
        return nonce! as Nonce
    }
    
    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> NSData? {
        let sealed: (NSData, Nonce)? = seal(message, recipientPublicKey: recipientPublicKey, senderSecretKey: senderSecretKey)
        if sealed == nil {
            return nil
        }
        let (authenticatedCipherText, nonce) = sealed!
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce)
        nonceAndAuthenticatedCipherText.appendData(message)
        return nonceAndAuthenticatedCipherText
    }
    
    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: NSData, nonce: Nonce)? {
        if recipientPublicKey.length != PublicKeyBytes || senderSecretKey.length != SecretKeyBytes {
            return nil
        }
        let authenticatedCipherText = NSMutableData(length: message.length + MacBytes)
        if authenticatedCipherText == nil {
            return nil
        }
        let nonce = self.nonce()
        if nonce == nil {
            return nil
        }
        if crypto_box_easy(UnsafeMutablePointer<UInt8>(authenticatedCipherText!.mutableBytes), UnsafePointer<UInt8>(message.bytes), CUnsignedLongLong(message.length), UnsafePointer<UInt8>(nonce!.bytes), UnsafePointer<UInt8>(recipientPublicKey.bytes), UnsafePointer<UInt8>(senderSecretKey.bytes)) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText!, nonce: nonce!)
    }

    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: NSData, nonce: Nonce, mac: MAC)? {
        if recipientPublicKey.length != PublicKeyBytes || senderSecretKey.length != SecretKeyBytes {
            return nil
        }
        let authenticatedCipherText = NSMutableData(length: message.length + MacBytes)
        if authenticatedCipherText == nil {
            return nil
        }
        let mac = NSMutableData(length: MacBytes)
        if mac == nil {
            return nil
        }
        let nonce = self.nonce()
        if nonce == nil {
            return nil
        }
        if crypto_box_detached(UnsafeMutablePointer<UInt8>(authenticatedCipherText!.mutableBytes), UnsafeMutablePointer<UInt8>(mac!.mutableBytes), UnsafePointer<UInt8>(message.bytes), CUnsignedLongLong(message.length), UnsafePointer<UInt8>(nonce!.bytes), UnsafePointer<UInt8>(recipientPublicKey.bytes), UnsafePointer<UInt8>(senderSecretKey.bytes)) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText!, nonce: nonce! as Nonce, mac: mac! as MAC)
    }
}
