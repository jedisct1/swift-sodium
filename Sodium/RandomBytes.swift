//
//  RandomBytes.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class RandomBytes {
    public func buf(length: Int) -> Data? {
        if length < 0 {
            return nil
        }
        var output = Data(count: length)
        output.withUnsafeMutableBytes { outputPtr in
            randombytes_buf(outputPtr, output.count)
        }
        return output
    }

    public func random() -> UInt32 {
        return randombytes_random()
    }

    public func uniform(upperBound: UInt32) -> UInt32 {
        return randombytes_uniform(upperBound)
    }
}
