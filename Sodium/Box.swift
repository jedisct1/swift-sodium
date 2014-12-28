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
    
    public struct KeyPair {
        public let pk: PublicKey
        public let sk: SecretKey
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
        return KeyPair(pk: NSData(data: pk!), sk: NSData(data: sk!))
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
        return KeyPair(pk: PublicKey(data: pk!), sk: SecretKey(data: sk!))
    }
    
    public func seal(message: NSData, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: NSData, nonce: NSData)? {
        let sealed = NSMutableData(length: message.length + MacBytes)
        if sealed == nil {
            return nil
        }
        return nil
    }
}