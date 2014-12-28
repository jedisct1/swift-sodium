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
        sodium_memzero(UnsafeMutablePointer<Void>(data.mutableBytes), UInt(data.length))
        data.length = 0
    }
    
    public func equals(b1: NSData, _ b2: NSData) -> Bool {
        if b1.length != b2.length {
            return false
        }
        let res = sodium_memcmp(UnsafePointer<Void>(b1.bytes), UnsafePointer<Void>(b2.bytes), UInt(b1.length))
        return res == 0;
    }
    
    public func bin2hex(bin: NSData) -> String? {
        let hexData = NSMutableData(length: bin.length * 2 + 1)
        if hexData == nil {
            return nil
        }
        let hexDataBytes = UnsafeMutablePointer<CChar>(hexData!.mutableBytes)
        if sodium_bin2hex(hexDataBytes, UInt(hexData!.length), UnsafePointer<UInt8>(bin.bytes), UInt(bin.length)) == nil {
            return nil
        }
        return String.fromCString(hexDataBytes)
    }
    
    public func hex2bin(hex: String, ignore: String? = nil) -> NSData? {
        let hexData = hex.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        if hexData == nil {
            return nil
        }
        let hexDataLen = hexData!.length
        let binDataCapacity = hexDataLen / 2
        let binData = NSMutableData(length: binDataCapacity)
        if binData == nil {
            return nil
        }
        var binDataLen: UInt = 0
        let ignore_cstr = ignore != nil ? (ignore! as NSString).UTF8String : nil
        if sodium_hex2bin(UnsafeMutablePointer<UInt8>(binData!.mutableBytes), UInt(binDataCapacity),UnsafePointer<CChar>(hexData!.bytes), UInt(hexDataLen), ignore_cstr, &binDataLen, nil) != 0 {
            return nil
        }
        binData!.length = Int(binDataLen)
        return binData
    }
}
