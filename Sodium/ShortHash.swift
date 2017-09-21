//
//  ShortHash.swift
//  Sodium
//
//  Created by Frank Denis on 12/28/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation
import libsodium

public class ShortHash {
    public let Bytes = Int(crypto_shorthash_bytes())
    public let KeyBytes = Int(crypto_shorthash_keybytes())
    
    public typealias Key = Data
    
    /**
     Generates a secret key.
     
     - Returns: The generated key.
     */
    public func key() -> Key? {
        var k = Data(count: KeyBytes)
        k.withUnsafeMutableBytes { kPtr in
            crypto_shorthash_keygen(kPtr)
        }
        return k
    }
    
    /**
     Computes short but unpredictable (without knowing the secret key) values suitable for picking a list in a hash table for a given key.
     
     - Parameter message: The data to be hashed.
     - Parameter key: The hash key.  Must be of length `KeyBytes`. Can be created using `RandomBytes.buf()`.
     
     - Returns: The computed fingerprint.  Will be of length `Bytes`.
     */
    public func hash(message: Data, key: Data) -> Data? {
        if key.count != KeyBytes {
            return nil
        }
        
        var output = Data(count: Bytes)
        
        let result = output.withUnsafeMutableBytes { outputPtr in
            return message.withUnsafeBytes { messagePtr in
                return key.withUnsafeBytes { keyPtr in
                    return crypto_shorthash(outputPtr, messagePtr, CUnsignedLongLong(message.count), keyPtr)
                }
            }
        }
        
        if result != 0 {
            return nil
        }
        
        return output
    }
}
