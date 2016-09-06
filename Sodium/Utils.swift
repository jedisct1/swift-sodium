//
//  Utils.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class Utils {
    public func zero(data: NSMutableData) {
        sodium_memzero(UnsafeMutableRawPointer(data.mutableBytes), data.length)
        data.length = 0
    }
    
    public func equals(b1: NSData, _ b2: NSData) -> Bool {
        if b1.length != b2.length {
            return false
        }
        let res = sodium_memcmp(UnsafeRawPointer(b1.bytes), UnsafeRawPointer(b2.bytes), b1.length)
        return res == 0;
    }
    
    public func compare(b1: NSData, _ b2: NSData) -> Int? {
        if b1.length != b2.length {
            return nil
        }
        let res = sodium_compare(b1.bytesPtr(), b2.bytesPtr(), b1.length)
        return Int(res);
    }
    
    public func bin2hex(bin: NSData) -> String? {
        guard let hexData = NSMutableData(length: bin.length * 2 + 1) else {
            return nil
        }
        if sodium_bin2hex(hexData.mutableBytesPtr(), hexData.length, bin.bytesPtr(), bin.length) == nil {
            return nil
        }
        return String.init(validatingUTF8: hexData.mutableBytesPtr())
    }
    
    public func hex2bin(hex: String, ignore: String? = nil) -> NSData? {
        guard let hexData = hex.data(using: String.Encoding.utf8, allowLossyConversion: false) else {
            return nil
        }
        let hexDataLen = hexData.count
        let binDataCapacity = hexDataLen / 2
        guard let binData = NSMutableData(length: binDataCapacity) else {
            return nil
        }
        var binDataLen: size_t = 0
        let ignore_cstr = ignore != nil ? (ignore! as NSString).utf8String : nil
        if sodium_hex2bin(binData.mutableBytesPtr(), binDataCapacity,(hexData as NSData).bytesPtr(), hexDataLen, ignore_cstr, &binDataLen, nil) != 0 {
            return nil
        }
        binData.length = Int(binDataLen)
        return binData
    }
}
