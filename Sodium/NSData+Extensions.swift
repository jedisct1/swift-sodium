//
//  InternalExtensions.swift
//  Sodium
//
//  Created by Frank Denis on 1/6/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Foundation

public extension NSData {
    var bytesPtr: UnsafePointer<UInt8> {
        return UnsafePointer<UInt8>(self.bytes)
    }
}

public extension NSMutableData {
    var mutableBytesPtr: UnsafeMutablePointer<UInt8> {
        return UnsafeMutablePointer<UInt8>(self.mutableBytes)
    }
}
