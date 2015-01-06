//
//  RandomBytes.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class RandomBytes {
    public func buf(length: Int) -> NSData? {
        if length < 0 {
            return nil
        }
        let output = NSMutableData(length: length)
        if output == nil {
            return nil
        }
        randombytes_buf(output!.mutableBytesPtr, UInt(output!.length))
        return output
    }
    
    public func random() -> UInt32 {
        return randombytes_random()
    }
    
    public func uniform(upperBound: UInt32) -> UInt32 {
        return randombytes_uniform(upperBound)
    }
}
