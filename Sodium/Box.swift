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
    public let BeforenmBytes = Int(crypto_box_beforenmbytes())
    public let SealBytes = Int(crypto_box_sealbytes())
    
    public typealias PublicKey = NSData
    public typealias SecretKey = NSData
    public typealias Nonce = NSData
    public typealias MAC = NSData
    public typealias Beforenm = NSData

    public struct KeyPair {
        public let publicKey: PublicKey
        public let secretKey: SecretKey

        public init(publicKey: PublicKey, secretKey: SecretKey) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }
    
    public func keyPair() -> KeyPair? {
        guard let pk = NSMutableData(length: PublicKeyBytes) else {
            return nil
        }
        guard let sk = NSMutableData(length: SecretKeyBytes) else {
            return nil
        }
        if crypto_box_keypair(pk.mutableBytesPtr, sk.mutableBytesPtr) != 0 {
            return nil
        }
        return KeyPair(publicKey: PublicKey(data: pk), secretKey: SecretKey(data: sk))
    }
    
    public func keyPair(seed seed: NSData) -> KeyPair? {
        if seed.length != SeedBytes {
            return nil
        }
        guard let pk = NSMutableData(length: PublicKeyBytes) else {
            return nil
        }
        guard let sk = NSMutableData(length: SecretKeyBytes) else {
            return nil
        }
        if crypto_box_seed_keypair(pk.mutableBytesPtr, sk.mutableBytesPtr, seed.bytesPtr) != 0 {
            return nil
        }
        return KeyPair(publicKey: PublicKey(data: pk), secretKey: SecretKey(data: sk))
    }
    
    public func nonce() -> Nonce? {
        guard let nonce = NSMutableData(length: NonceBytes) else {
            return nil
        }
        randombytes_buf(nonce.mutableBytesPtr, nonce.length)
        return nonce as Nonce
    }
    
    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> NSData? {
        guard let (authenticatedCipherText, nonce): (NSData, Nonce) = seal(message, recipientPublicKey: recipientPublicKey, senderSecretKey: senderSecretKey) else {
            return nil
        }
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce)
        nonceAndAuthenticatedCipherText.appendData(authenticatedCipherText)
        return nonceAndAuthenticatedCipherText
    }
    
    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: NSData, nonce: Nonce)? {
        if recipientPublicKey.length != PublicKeyBytes || senderSecretKey.length != SecretKeyBytes {
            return nil
        }
        guard let authenticatedCipherText = NSMutableData(length: message.length + MacBytes) else {
            return nil
        }
        guard let nonce = self.nonce() else {
            return nil
        }
        if crypto_box_easy(authenticatedCipherText.mutableBytesPtr, message.bytesPtr, CUnsignedLongLong(message.length), nonce.bytesPtr, recipientPublicKey.bytesPtr, senderSecretKey.bytesPtr) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: NSData, nonce: Nonce, mac: MAC)? {
        if recipientPublicKey.length != PublicKeyBytes || senderSecretKey.length != SecretKeyBytes {
            return nil
        }
        guard let authenticatedCipherText = NSMutableData(length: message.length) else {
            return nil
        }
        guard let mac = NSMutableData(length: MacBytes) else {
            return nil
        }
        guard let nonce = self.nonce() else {
            return nil
        }
        if crypto_box_detached(authenticatedCipherText.mutableBytesPtr, mac.mutableBytesPtr, message.bytesPtr, CUnsignedLongLong(message.length), nonce.bytesPtr, recipientPublicKey.bytesPtr, senderSecretKey.bytesPtr) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce as Nonce, mac: mac as MAC)
    }
    
    public func open(nonceAndAuthenticatedCipherText: NSData, senderPublicKey: PublicKey, recipientSecretKey: SecretKey) -> NSData? {
        if nonceAndAuthenticatedCipherText.length < NonceBytes + MacBytes {
            return nil
        }
        let nonce = nonceAndAuthenticatedCipherText.subdataWithRange(NSRange(0..<NonceBytes)) as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdataWithRange(NSRange(NonceBytes..<nonceAndAuthenticatedCipherText.length))
        return open(authenticatedCipherText, senderPublicKey: senderPublicKey, recipientSecretKey: recipientSecretKey, nonce: nonce)
    }
    
    public func open(authenticatedCipherText: NSData, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce) -> NSData? {
        if nonce.length != NonceBytes || authenticatedCipherText.length < MacBytes {
            return nil
        }
        if senderPublicKey.length != PublicKeyBytes || recipientSecretKey.length != SecretKeyBytes {
            return nil
        }
        guard let message = NSMutableData(length: authenticatedCipherText.length - MacBytes) else {
            return nil
        }
        if crypto_box_open_easy(message.mutableBytesPtr, authenticatedCipherText.bytesPtr, CUnsignedLongLong(authenticatedCipherText.length), nonce.bytesPtr, senderPublicKey.bytesPtr, recipientSecretKey.bytesPtr) != 0 {
            return nil
        }
        return message
    }
    
    public func open(authenticatedCipherText: NSData, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce, mac: MAC) -> NSData? {
        if nonce.length != NonceBytes || mac.length != MacBytes {
            return nil
        }
        if senderPublicKey.length != PublicKeyBytes || recipientSecretKey.length != SecretKeyBytes {
            return nil
        }
        guard let message = NSMutableData(length: authenticatedCipherText.length) else {
            return nil
        }
        if crypto_box_open_detached(message.mutableBytesPtr, authenticatedCipherText.bytesPtr, mac.bytesPtr, CUnsignedLongLong(authenticatedCipherText.length), nonce.bytesPtr, senderPublicKey.bytesPtr, recipientSecretKey.bytesPtr) != 0 {
            return nil
        }
        return message
    }
    
    public func beforenm(recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> NSData? {
        let key = NSMutableData(length: BeforenmBytes)
        if crypto_box_beforenm(key!.mutableBytesPtr, recipientPublicKey.bytesPtr, senderSecretKey.bytesPtr) != 0 {
            return nil
        }
        return key
    }
    
    public func seal(message: NSData, beforenm: Beforenm) -> (authenticatedCipherText: NSData, nonce: Nonce)? {
        if beforenm.length != BeforenmBytes {
            return nil
        }
        guard let authenticatedCipherText = NSMutableData(length: message.length + MacBytes) else {
            return nil
        }
        guard let nonce = self.nonce() else {
            return nil
        }
        if crypto_box_easy_afternm(authenticatedCipherText.mutableBytesPtr, message.bytesPtr, CUnsignedLongLong(message.length), nonce.bytesPtr, beforenm.bytesPtr) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }
    
    public func open(nonceAndAuthenticatedCipherText: NSData, beforenm: Beforenm) -> NSData? {
        if nonceAndAuthenticatedCipherText.length < NonceBytes + MacBytes {
            return nil
        }
        let nonce = nonceAndAuthenticatedCipherText.subdataWithRange(NSRange(0..<NonceBytes)) as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdataWithRange(NSRange(NonceBytes..<nonceAndAuthenticatedCipherText.length))
        return open(authenticatedCipherText, beforenm: beforenm, nonce: nonce)
    }

    public func open(authenticatedCipherText: NSData, beforenm: Beforenm, nonce: Nonce) -> NSData? {
        if nonce.length != NonceBytes || authenticatedCipherText.length < MacBytes {
            return nil
        }
        if beforenm.length != BeforenmBytes {
            return nil
        }
        guard let message = NSMutableData(length: authenticatedCipherText.length - MacBytes) else {
            return nil
        }
        if crypto_box_open_easy_afternm(message.mutableBytesPtr, authenticatedCipherText.bytesPtr, CUnsignedLongLong(authenticatedCipherText.length), nonce.bytesPtr, beforenm.bytesPtr) != 0 {
            return nil
        }
        return message
    }

    public func seal(message: NSData, beforenm: Beforenm) -> NSData? {
        guard let (authenticatedCipherText, nonce): (NSData, Nonce) = seal(message, beforenm: beforenm) else {
            return nil
        }
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce)
        nonceAndAuthenticatedCipherText.appendData(authenticatedCipherText)
        return nonceAndAuthenticatedCipherText
    }
    
    public func seal(message: NSData, recipientPublicKey: Box.PublicKey) -> NSData? {
        if recipientPublicKey.length != PublicKeyBytes {
            return nil
        }
        guard let anonymousCipherText = NSMutableData(length: SealBytes + message.length) else {
            return nil
        }
        if crypto_box_seal(anonymousCipherText.mutableBytesPtr, message.bytesPtr, CUnsignedLongLong(message.length), recipientPublicKey.bytesPtr) != 0 {
            return nil
        }
        return anonymousCipherText
    }
    
    public func open(anonymousCipherText: NSData, recipientPublicKey: PublicKey, recipientSecretKey: SecretKey) -> NSData? {
        if recipientPublicKey.length != PublicKeyBytes || recipientSecretKey.length != SecretKeyBytes || anonymousCipherText.length < SealBytes {
            return nil
        }
        let message = NSMutableData(length: anonymousCipherText.length - SealBytes)
        if message == nil {
            return nil
        }
        if crypto_box_seal_open(message!.mutableBytesPtr, anonymousCipherText.bytesPtr, CUnsignedLongLong(anonymousCipherText.length), recipientPublicKey.bytesPtr, recipientSecretKey.bytesPtr) != 0 {
            return nil
        }
        return message
    }
}
