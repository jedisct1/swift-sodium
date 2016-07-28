//
//  Stream.swift
//  Sodium
//
//  Created by AlexChen on 28/7/2016.
//  Copyright © 2016 Frank Denis. All rights reserved.
//

import Foundation

public class Stream {
    
    var cipherName : Ciphers!
    var key: NSData!
    var iv: NSData!
    var counter = 0
    
    let BLOCK_SIZE = 64
    var buf_size = 2048
    
    var buffer: NSMutableData!
    
    typealias CipherFunctionAlias = (UnsafeMutablePointer<UInt8>, UnsafePointer<UInt8>, UInt64, UnsafePointer<UInt8>, UInt64, UnsafePointer<UInt8>) -> Int32
    
    var cipherFunction: CipherFunctionAlias!
    
    public enum Ciphers: UInt, CustomStringConvertible {
        case Chacha20 = 0
        case Salsa20 = 1
        public var description: String {
            switch self {
            case .Chacha20:
                return "chacha20"
            case .Salsa20:
                return "salsa20"
            }
        }
    }
    
    public func initStream(cipher: Ciphers = .Chacha20, key: NSData, iv: NSData) {
        self.cipherName = cipher
        self.key = key
        self.iv = iv
        self.counter = 0
        self.buffer = NSMutableData(length: buf_size)
        
        switch cipher {
        case .Chacha20:
            self.cipherFunction = crypto_stream_chacha20_xor_ic
        case .Salsa20:
            self.cipherFunction = crypto_stream_salsa20_xor_ic
        }
        
        
    }
    
    public func update(input: NSData) -> NSData?{
        
        var len = input.length
        var padding = counter % BLOCK_SIZE
        if buf_size < padding + len {
            buf_size = (padding + len) * 2
            buffer = NSMutableData(length: buf_size)
        }
        guard let plainMessage = NSMutableData(length: buf_size) else { return nil }

        plainMessage.replaceBytesInRange(NSMakeRange(padding, len), withBytes: input.bytes)
        
        
        
        var succeed = cipherFunction(
            buffer.mutableBytesPtr,
            plainMessage.bytesPtr,
            UInt64(padding+len), iv.bytesPtr, UInt64(counter/BLOCK_SIZE), key.bytesPtr)
        
        guard succeed == 0 else { return nil }
        self.counter += len
        
        return buffer.subdataWithRange(NSMakeRange(padding, len))
    }
}