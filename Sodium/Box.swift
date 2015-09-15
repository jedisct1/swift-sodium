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
        if crypto_box_keypair(pk!.mutableBytesPtr, sk!.mutableBytesPtr) != 0 {
            return nil
        }
        return KeyPair(publicKey: PublicKey(data: pk!), secretKey: SecretKey(data: sk!))
    }
    
    public func keyPair(#seed: NSData) -> KeyPair? {
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
        if crypto_box_seed_keypair(pk!.mutableBytesPtr, sk!.mutableBytesPtr, seed.bytesPtr) != 0 {
            return nil
        }
        return KeyPair(publicKey: PublicKey(data: pk!), secretKey: SecretKey(data: sk!))
    }
    
    public func nonce() -> Nonce? {
        let nonce = NSMutableData(length: NonceBytes)
        if nonce == nil {
            return nil
        }
        randombytes_buf(nonce!.mutableBytesPtr, nonce!.length)
        return nonce! as Nonce
    }
    
    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> NSData? {
        let sealed: (NSData, Nonce)? = seal(message, recipientPublicKey: recipientPublicKey, senderSecretKey: senderSecretKey)
        if sealed == nil {
            return nil
        }
        let (authenticatedCipherText, nonce) = sealed!
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce)
        nonceAndAuthenticatedCipherText.appendData(authenticatedCipherText)
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
        if crypto_box_easy(authenticatedCipherText!.mutableBytesPtr, message.bytesPtr, CUnsignedLongLong(message.length), nonce!.bytesPtr, recipientPublicKey.bytesPtr, senderSecretKey.bytesPtr) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText!, nonce: nonce!)
    }

    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: NSData, nonce: Nonce, mac: MAC)? {
        if recipientPublicKey.length != PublicKeyBytes || senderSecretKey.length != SecretKeyBytes {
            return nil
        }
        let authenticatedCipherText = NSMutableData(length: message.length)
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
        if crypto_box_detached(authenticatedCipherText!.mutableBytesPtr, mac!.mutableBytesPtr, message.bytesPtr, CUnsignedLongLong(message.length), nonce!.bytesPtr, recipientPublicKey.bytesPtr, senderSecretKey.bytesPtr) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText!, nonce: nonce! as Nonce, mac: mac! as MAC)
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
        let message = NSMutableData(length: authenticatedCipherText.length - MacBytes)
        if message == nil {
            return nil
        }
        if crypto_box_open_easy(message!.mutableBytesPtr, authenticatedCipherText.bytesPtr, CUnsignedLongLong(authenticatedCipherText.length), nonce.bytesPtr, senderPublicKey.bytesPtr, recipientSecretKey.bytesPtr) != 0 {
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
        let message = NSMutableData(length: authenticatedCipherText.length)
        if message == nil {
            return nil
        }
        if crypto_box_open_detached(message!.mutableBytesPtr, authenticatedCipherText.bytesPtr, mac.bytesPtr, CUnsignedLongLong(authenticatedCipherText.length), nonce.bytesPtr, senderPublicKey.bytesPtr, recipientSecretKey.bytesPtr) != 0 {
            return nil
        }
        return message
    }
}
