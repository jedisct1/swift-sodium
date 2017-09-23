//
//  Utils.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation
import libsodium

public class Utils {
    
    /**
     Tries to effectively zero bytes in `data`, even if optimizations are being applied to the code.
     
     - Parameter data: The `Data` object to zero.
     */
    public func zero(_ data: inout Data)  {
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
    public func bin2hex(_ bin: Data) -> String? {
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
    public func hex2bin(_ hex: String, ignore: String? = nil) -> Data? {
        guard let hexData = hex.data(using: .utf8, allowLossyConversion: false) else {
            return nil
        }
        
        let hexDataLen = hexData.count
        let binDataCapacity = hexDataLen / 2
        var binData = Data(count: binDataCapacity)
        var binDataLen: size_t = 0
        let ignore_cstr = ignore != nil ? (ignore! as NSString).utf8String : nil
        
        let result = binData.withUnsafeMutableBytes { binPtr in
            return hexData.withUnsafeBytes { hexPtr in
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
    
    public enum Base64Variant: CInt {
        case ORIGINAL            = 1
        case ORIGINAL_NO_PADDING = 3
        case URLSAFE             = 5
        case URLSAFE_NO_PADDING  = 7
    }
    
    /**
     Converts bytes stored in `bin` into a Base64 representation.
     
     - Parameter bin: The data to encode as Base64.
     - Parameter variant: the Base64 variant to use. By default: URLSAFE.
     
     - Returns: The encoded base64 string.
     */
    public func bin2base64(_ bin: Data, variant: Base64Variant = Base64Variant.URLSAFE) -> String? {
        var b64Data = Data(count: sodium_base64_encoded_len(bin.count, variant.rawValue))
        return b64Data.withUnsafeMutableBytes { (b64Ptr: UnsafeMutablePointer<Int8>) -> String? in
            return bin.withUnsafeBytes { (binPtr: UnsafePointer<UInt8>) -> String? in
                if sodium_bin2base64(b64Ptr, b64Data.count, binPtr, bin.count, variant.rawValue) == nil {
                    return nil
                }                
                return String.init(validatingUTF8: b64Ptr)
            }
        }
    }
    
    /*
     Decode as a base64 string, ignoring characters included for readability.
     
     - Parameter b64: The base64 string to decode.
     - Parameter ignore: Optional string containing readability characters to ignore during decoding.
     
     - Returns: The decoded data.
     */
    public func base642bin(_ b64: String, variant: Base64Variant = Base64Variant.URLSAFE, ignore: String? = nil) -> Data? {
        guard let b64Data = b64.data(using: .utf8, allowLossyConversion: false) else {
            return nil
        }
        
        let b64DataLen = b64Data.count
        let binDataCapacity = b64DataLen * 3 / 4
        var binData = Data(count: binDataCapacity)
        var binDataLen: size_t = 0
        let ignore_cstr = ignore != nil ? (ignore! as NSString).utf8String : nil
        
        let result = binData.withUnsafeMutableBytes { binPtr in
            return b64Data.withUnsafeBytes { b64Ptr in
                return sodium_base642bin(binPtr,
                                         binDataCapacity,
                                         b64Ptr,
                                         b64DataLen,
                                         ignore_cstr,
                                         &binDataLen,
                                         nil, variant.rawValue)
            }
        }
        
        if  result != 0 {
            return nil
        }
        
        binData.count = Int(binDataLen)
        return binData
    }
}
