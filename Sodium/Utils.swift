//
//  Utils.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class Utils {

    /**
     Tries to effectively zero bytes in `data`, even if optimizations are being applied to the code.
     
     - Parameter data: The `Data` object to zero.
     */
    public func zero(data: inout Data)  {
      let count = data.count
      data.withUnsafeMutableBytes { (dataPtr: UnsafeMutablePointer<UInt8>) in
        let rawPtr = UnsafeMutableRawPointer(dataPtr)
        sodium_memzero(rawPtr, count)
        return
      }
    }

    /**
     - Returns: `true` if the bytes in `b1` match the bytes in `b2`. Otherwise, it returns false.
     */
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

    /**
     - Returns: 0 if the bytes in `b1` match the bytes in `b2`. Otherwise, it returns -1.
     */
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

    /**
     Converts bytes stored in `bin` into a hexadecimal string.
     
     - Parameter bin: The data to encode as hexdecimal.
     
     - Returns: The encoded hexdecimal string.
     */
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

    /**
     Decode as a hexdecimal string, ignoring characters included for readability.
     
     - Parameter hex: The hexdecimal string to decode.
     - Parameter ignore: Optional string containing readability characters to ignore during decoding.
     
     - Returns: The decoded data.
     */
    public func hex2bin(hex: String, ignore: String? = nil) -> Data? {
        guard var hexData = hex.data(using: .utf8, allowLossyConversion: false) else {
            return nil
        }

        let hexDataLen = hexData.count
        let binDataCapacity = hexDataLen / 2
        var binData = Data(count: binDataCapacity)
        var binDataLen: size_t = 0
        let ignore_cstr = ignore != nil ? (ignore! as NSString).utf8String : nil

        let result = binData.withUnsafeMutableBytes { binPtr in
          return hexData.withUnsafeMutableBytes { hexPtr in
            return sodium_hex2bin(binPtr,
                                  binDataCapacity,
                                  hexPtr,
                                  hexDataLen,
                                  ignore_cstr,
                                  &binDataLen,
                                  nil)
          }
        }

        if  result != 0 {
            return nil
        }

        binData.count = Int(binDataLen)
        return binData
    }
}
