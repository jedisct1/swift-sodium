//
//  GenericHash.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class GenericHash {
    public let BytesMin = Int(crypto_generichash_bytes_min())
    public let BytesMax = Int(crypto_generichash_bytes_max())
    public let Bytes = Int(crypto_generichash_bytes())
    public let KeybytesMin = Int(crypto_generichash_keybytes_min())
    public let KeybytesMax = Int(crypto_generichash_keybytes_max())
    public let Keybytes = Int(crypto_generichash_keybytes())
    public let Primitive = String.fromCString(crypto_generichash_primitive())
    
    public func hash(message: NSData, key: NSData? = nil) -> NSData? {
        return hash(message, key: key, outputLength: Bytes)
    }
    
    public func hash(message: NSData, key: NSData?, outputLength: Int) -> NSData? {
        let output = NSMutableData(length: outputLength)
        if output == nil {
            return nil
        }
        var ret: CInt;
        if let key = key {
            ret = crypto_generichash(UnsafeMutablePointer<UInt8>(output!.mutableBytes), UInt(output!.length), UnsafePointer<UInt8>(message.bytes), CUnsignedLongLong(message.length), UnsafePointer<UInt8>(key.bytes), UInt(key.length))
        } else {
            ret = crypto_generichash(UnsafeMutablePointer<UInt8>(output!.mutableBytes), UInt(output!.length), UnsafePointer<UInt8>(message.bytes), CUnsignedLongLong(message.length), nil, 0)
        }
        if ret != 0 {
            return nil
        }
        return output
    }

    public func hash(message: NSData, outputLength: Int) -> NSData? {
        return hash(message, key: NSData(), outputLength: outputLength)
    }
    
    public func initStream(key: NSData? = nil) -> Stream? {
        return Stream(key: key, outputLength: Bytes)
    }
    
    public func initStream(key: NSData?, outputLength: Int) -> Stream? {
        return Stream(key: key, outputLength: outputLength)
    }
    
    public func initStream(outputLength: Int) -> Stream? {
        return Stream(key: nil, outputLength: outputLength)
    }

    public class Stream {
        public var outputLength: Int = 0;
        private var state: UnsafeMutablePointer<crypto_generichash_state>?;

        init?(key: NSData?, outputLength: Int) {
            state = UnsafeMutablePointer<crypto_generichash_state>.alloc(1);
            if state == nil {
                return nil
            }
            var ret: CInt
            if let key = key {
                ret = crypto_generichash_init(state!, UnsafePointer<UInt8>(key.bytes), UInt(key.length), UInt(outputLength))
            } else {
                ret = crypto_generichash_init(state!, nil, 0, UInt(outputLength))
            }
            if (ret != 0) {
                return nil
            }
            self.outputLength = outputLength;
        }
    
        deinit {
            state?.dealloc(1)
        }
    
        public func update(input: NSData) -> Bool {
            return crypto_generichash_update(state!, UnsafePointer<UInt8>(input.bytes), CUnsignedLongLong(input.length)) == 0
        }
    
        public func final() -> NSData? {
            let output = NSMutableData(length: outputLength)
            if (crypto_generichash_final(state!, UnsafeMutablePointer<UInt8>(output!.mutableBytes), UInt(output!.length)) != 0) {
                return nil
            }
            return output
        }
    }
}
