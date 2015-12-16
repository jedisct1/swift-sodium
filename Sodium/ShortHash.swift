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
        guard let output = NSMutableData(length: Bytes) else {
            return nil
        }
        if crypto_shorthash(output.mutableBytesPtr, message.bytesPtr, CUnsignedLongLong(message.length), key.bytesPtr) != 0 {
            return nil
        }
        return output
    }
}
