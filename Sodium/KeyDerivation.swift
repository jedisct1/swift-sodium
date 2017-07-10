//
//  KeyDerivation.swift
//  Sodium
//
//  Created by Patrick Salami (https://www.github.com/psalami) on 7/7/17.
//  Copyright © 2017 Frank Denis. All rights reserved.
//

import Foundation
import libsodium

public class KeyDerivation {
    public typealias Key = Data
    public typealias SubKey = Data
    public let BytesMin = Int(crypto_kdf_bytes_min())
    public let BytesMax = Int(crypto_kdf_bytes_max())
    public let KeyBytes = Int(crypto_kdf_keybytes())
    public let ContextBytes = Int(crypto_kdf_contextbytes())

    /**
     Derives a subkey from the specified input key. Each index (from 0 to (2^64) - 1) yields a unique deterministic subkey.
     The sequence of subkeys is likely unique for a given context.

     - Parameter secretKey: the master key from which to derive the subkey (must be between 16 and 64 bytes in length, inclusive)
     - Parameter index: the index of the subkey to generate (allowed range: 0 to (2^64) - 1)
     - Parameter length: the desired length of the subkey in bytes (allowed range: 16 to 64; default: 32)
     - Parameter context: a String that identifies the context; use a different value for different types of keys (should be exactly 8 characters long but must be no longer than 8 characters)
     - Returns: the derived key or nil on error.

     - Note: Input and output keys must have a length between 16 and 64 bytes (inclusive), otherwise an error is returned. Context must be at most 8 characters long. If the specified context is shorter than 8 characters, it will be padded to 8 characters.

     */
    public func derive(secretKey: Data, index: UInt64, length: Int, context: String) -> Data? {
        if length < BytesMin {
            return nil
        }

        if length > BytesMax {
            return nil
        }

        if secretKey.count != KeyBytes {
            return nil
        }

        var contextBin = [UInt8](context.utf8)
        if contextBin.count > ContextBytes {
            return nil
        }
        while contextBin.count < ContextBytes {
            contextBin += [0]
        }

        var subKey = Data(count: length)

        let result = subKey.withUnsafeMutableBytes { subKeyPtr in
            return secretKey.withUnsafeBytes { secretKeyPtr in
                return contextBin.withUnsafeBytes { contextBinPtr in
                    return crypto_kdf_derive_from_key(subKeyPtr, length, index, contextBinPtr, secretKeyPtr)
                }
            }
        }
        if result != 0 {
            return nil
        }
        return subKey
    }
}
