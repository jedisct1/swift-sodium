//
//  ShortHash.swift
//  Sodium
//
//  Created by Frank Denis on 12/28/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class ShortHash {
    public let Bytes = Int(crypto_shorthash_bytes())
    public let KeyBytes = Int(crypto_shorthash_keybytes())
    
    public func hash(message: NSData, key: NSData) -> NSData? {
        if key.length != KeyBytes {
            return nil
        }
        let output = NSMutableData(length: Bytes)
        if output == nil {
            return nil
        }
        if crypto_shorthash(UnsafeMutablePointer<UInt8>(output!.mutableBytes), UnsafePointer<UInt8>(message.bytes), CUnsignedLongLong(message.length), UnsafePointer<UInt8>(key.bytes)) != 0 {
            return nil
        }
        return output
    }
}