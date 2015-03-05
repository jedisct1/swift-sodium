//
//  SecretBox.swift
//  Sodium
//
//  Created by Devin Chalmers on 1/4/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Foundation

public class SecretBox {
    public let KeyBytes = Int(crypto_secretbox_keybytes())
    public let NonceBytes = Int(crypto_secretbox_noncebytes())
    public let MacBytes = Int(crypto_secretbox_macbytes())
    
    public typealias Key = NSData
    public typealias Nonce = NSData
    public typealias MAC = NSData
    
    public func key() -> Key? {
        let k = NSMutableData(length: KeyBytes)
        if k == nil {
            return nil
        }
        randombytes_buf(k!.mutableBytesPtr, k!.length)
        return k
    }
    
    public func nonce() -> Nonce? {
        let n = NSMutableData(length: NonceBytes)
        if n == nil {
            return nil
        }
        randombytes_buf(n!.mutableBytesPtr, n!.length)
        return n
    }
    
    public func seal(message: NSData, secretKey: Key) -> NSData? {
        let sealed: (NSData, Nonce)? = seal(message, secretKey: secretKey)
        if sealed == nil {
            return nil
        }
        let (authenticatedCipherText, nonce) = sealed!
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce)
        nonceAndAuthenticatedCipherText.appendData(authenticatedCipherText)
        return nonceAndAuthenticatedCipherText
    }
    
    public func seal(message: NSData, secretKey: Key) -> (authenticatedCipherText: NSData, nonce: Nonce)? {
        if secretKey.length != KeyBytes {
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
        if crypto_secretbox_easy(authenticatedCipherText!.mutableBytesPtr, message.bytesPtr, UInt64(message.length), nonce!.bytesPtr, secretKey.bytesPtr) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText!, nonce: nonce!)
    }
    
    public func seal(message: NSData, secretKey: Key) -> (cipherText: NSData, nonce: Nonce, mac: MAC)? {
        if secretKey.length != KeyBytes {
            return nil
        }
        let cipherText = NSMutableData(length: message.length)
        if cipherText == nil {
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
        if crypto_secretbox_detached(cipherText!.mutableBytesPtr, mac!.mutableBytesPtr, message.bytesPtr, UInt64(message.length), nonce!.bytesPtr, secretKey.bytesPtr) != 0 {
            return nil
        }
        return (cipherText: cipherText!, nonce: nonce!, mac: mac!)
    }
    
    public func open(nonceAndAuthenticatedCipherText: NSData, secretKey: Key) -> NSData? {
        if nonceAndAuthenticatedCipherText.length < MacBytes + NonceBytes {
            return nil
        }
        let message = NSMutableData(length: nonceAndAuthenticatedCipherText.length - MacBytes - NonceBytes)
        if message == nil {
            return nil
        }
        let nonce = nonceAndAuthenticatedCipherText.subdataWithRange(NSRange(0..<NonceBytes)) as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdataWithRange(NSRange(NonceBytes..<nonceAndAuthenticatedCipherText.length))
        return open(authenticatedCipherText, secretKey: secretKey, nonce: nonce)
    }
    
    public func open(authenticatedCipherText: NSData, secretKey: Key, nonce: Nonce) -> NSData? {
        if authenticatedCipherText.length < MacBytes {
            return nil
        }
        let message = NSMutableData(length: authenticatedCipherText.length - MacBytes)
        if message == nil {
            return nil
        }
        if crypto_secretbox_open_easy(message!.mutableBytesPtr, authenticatedCipherText.bytesPtr, UInt64(authenticatedCipherText.length), nonce.bytesPtr, secretKey.bytesPtr) != 0 {
            return nil
        }
        return message
    }
    
    public func open(cipherText: NSData, secretKey: Key, nonce: Nonce, mac: MAC) -> NSData? {
        if nonce.length != NonceBytes || mac.length != MacBytes {
            return nil
        }
        if secretKey.length != KeyBytes {
            return nil
        }
        let message = NSMutableData(length: cipherText.length)
        if message == nil {
            return nil
        }
        if crypto_secretbox_open_detached(message!.mutableBytesPtr, cipherText.bytesPtr, mac.bytesPtr, UInt64(cipherText.length), nonce.bytesPtr, secretKey.bytesPtr) != 0 {
            return nil
        }
        return message
    }
}
