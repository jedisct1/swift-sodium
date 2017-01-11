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
    public let Primitive = String.init(validatingUTF8: crypto_generichash_primitive())

    public func hash(message: Data, key: Data? = nil) -> Data? {
        return hash(message: message, key: key, outputLength: Bytes)
    }

    public func hash(message: Data, key: Data?, outputLength: Int) -> Data? {
        var output = Data(count: outputLength)
        var result: Int32 = -1

        if let key = key {
            result = output.withUnsafeMutableBytes { outputPtr in
                return message.withUnsafeBytes { messagePtr in
                    return key.withUnsafeBytes { keyPtr in
                        return crypto_generichash(
                          outputPtr,
                          output.count,
                          messagePtr,
                          CUnsignedLongLong(message.count),
                          keyPtr,
                          key.count)
                    }
                }
            }
        } else {
            result = output.withUnsafeMutableBytes { outputPtr in
                return message.withUnsafeBytes { messagePtr in
                    return crypto_generichash(
                      outputPtr,
                      output.count,
                      messagePtr,
                      CUnsignedLongLong(message.count),
                      nil,
                      0)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return output
    }

    public func hash(message: Data, outputLength: Int) -> Data? {
        return hash(message: message, key: nil, outputLength: outputLength)
    }

    public func initStream(key: Data? = nil) -> Stream? {
        return Stream(key: key, outputLength: Bytes)
    }

    public func initStream(key: Data?, outputLength: Int) -> Stream? {
        return Stream(key: key, outputLength: outputLength)
    }

    public func initStream(outputLength: Int) -> Stream? {
        return Stream(key: nil, outputLength: outputLength)
    }

    public class Stream {
        public var outputLength: Int = 0
        private var state: UnsafeMutablePointer<crypto_generichash_state>?

        init?(key: Data?, outputLength: Int) {
            state = UnsafeMutablePointer<crypto_generichash_state>.allocate(capacity: 1)
            guard let state = state else {
                return nil
            }

            var result: Int32 = -1

            if let key = key {
                result = key.withUnsafeBytes { keyPtr in
                    crypto_generichash_init(state, keyPtr, key.count, outputLength)
                }
            } else {
                result = crypto_generichash_init(state, nil, 0, outputLength)
            }

            if result != 0 {
                return nil
            }

            self.outputLength = outputLength;
        }

        deinit {
            state?.deallocate(capacity: 1)
        }

        public func update(input: Data) -> Bool {
            return input.withUnsafeBytes { inputPtr in
                return crypto_generichash_update(state!, inputPtr, CUnsignedLongLong(input.count)) == 0
            }
        }

        public func final() -> Data? {
            var output = Data(count: outputLength)
            let result = output.withUnsafeMutableBytes { outputPtr in
                crypto_generichash_final(state!, outputPtr, output.count)
            }

            if result != 0 {
                return nil
            }

            return output
        }
    }
}
