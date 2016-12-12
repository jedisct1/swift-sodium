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
    }

    public func zero(data: inout Data)  {
      let count = data.count
      data.withUnsafeMutableBytes { (dataPtr: UnsafeMutablePointer<UInt8>) in
        let rawPtr = UnsafeMutableRawPointer(dataPtr)
        sodium_memzero(rawPtr, count)
        return
      }
    }

    public func equals(_ b1: Data, _ b2: Data) -> Bool {
        if b1.count != b2.count {
            return false
        }

        return b1.withUnsafeBytes { b1Ptr in
          return b2.withUnsafeBytes { b2Ptr in
            return Int(sodium_memcmp(
                         UnsafeRawPointer(b1Ptr),
                         UnsafeRawPointer(b2Ptr),
                         b1.count)) == 0
          }
        }
    }

    public func equals(_ b1: NSData, _ b2: NSData) -> Bool {
      return equals(b1 as Data, b2 as Data)
    }

    public func compare(_ b1: Data, _ b2: Data) -> Int? {
        if b1.count != b2.count {
            return nil
        }

        return b1.withUnsafeBytes { b1Ptr in
          return b2.withUnsafeBytes { b2Ptr in
            return Int(sodium_compare(
                         b1Ptr,
                         b2Ptr,
                         b1.count))
          }
        }
    }

    public func compare(_ b1: NSData, _ b2: NSData) -> Int? {
      return compare(b1 as Data, b2 as Data)
    }

    public func bin2hex(bin: Data) -> String? {
        var hexData = Data(count: bin.count * 2 + 1)
        return hexData.withUnsafeMutableBytes { (hexPtr: UnsafeMutablePointer<Int8>) -> String? in
          return bin.withUnsafeBytes { (binPtr: UnsafePointer<UInt8>) -> String? in
            if sodium_bin2hex(hexPtr, hexData.count, binPtr, bin.count) == nil {
              return nil
            }

            return String.init(validatingUTF8: hexPtr)
          }
        }
    }

    public func bin2hex(bin: NSData) -> String? {
      return bin2hex(bin: bin as Data)
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
