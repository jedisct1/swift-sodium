//
//  InternalExtensions.swift
//  Sodium
//
//  Created by Frank Denis on 1/6/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Foundation

public extension NSData {
    func bytesPtr<T>() -> UnsafePointer<T>{
        let rawBytes = self.bytes
        return rawBytes.assumingMemoryBound(to: T.self);
    }
}

public extension NSMutableData {
    func mutableBytesPtr<T>() -> UnsafeMutablePointer<T>{
        let rawBytes = self.mutableBytes
        return rawBytes.assumingMemoryBound(to: T.self)
    }
}
