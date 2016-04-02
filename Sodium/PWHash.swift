//
//  PWHash.swift
//  Sodium
//
//  Created by Frank Denis on 4/29/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Foundation

public class PWHash {
    public let SaltBytes = Int(crypto_pwhash_saltbytes())
    public let StrBytes = Int(crypto_pwhash_strbytes()) - (1 as Int)
    public let StrPrefix = String(UTF8String: crypto_pwhash_strprefix())
    public let OpsLimitInteractive = Int(crypto_pwhash_opslimit_interactive())
    public let OpsLimitModerate = Int(crypto_pwhash_opslimit_moderate())
    public let OpsLimitSensitive = Int(crypto_pwhash_opslimit_sensitive())
    public let MemLimitInteractive = Int(crypto_pwhash_memlimit_interactive())
    public let MemLimitModerate = Int(crypto_pwhash_memlimit_moderate())
    public let MemLimitSensitive = Int(crypto_pwhash_memlimit_sensitive())

    public func str(passwd: NSData, opsLimit: Int, memLimit: Int) -> String? {
        guard let output = NSMutableData(length: StrBytes) else {
            return nil
        }
        if crypto_pwhash_str(UnsafeMutablePointer<CChar>(output.mutableBytes), UnsafePointer<CChar>(passwd.bytes), CUnsignedLongLong(passwd.length), CUnsignedLongLong(opsLimit), size_t(memLimit)) != 0 {
            return nil
        }
        return NSString(data: output, encoding: NSUTF8StringEncoding) as String?
    }

    public func strVerify(hash: String, passwd: NSData) -> Bool {
        guard let hashData = (hash + "\0").dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) else {
                return false
        }
        return crypto_pwhash_str_verify(UnsafePointer<CChar>(hashData.bytes), UnsafePointer<CChar>(passwd.bytes), CUnsignedLongLong(passwd.length)) == 0
    }

    public func hash(outputLength: Int, passwd: NSData, salt: NSData, opsLimit: Int, memLimit: Int) -> NSData? {
        if salt.length != SaltBytes {
            return nil
        }
        guard let output = NSMutableData(length: outputLength) else {
            return nil
        }
        if crypto_pwhash(output.mutableBytesPtr, CUnsignedLongLong(outputLength), UnsafePointer<CChar>(passwd.bytes), CUnsignedLongLong(passwd.length), salt.bytesPtr, CUnsignedLongLong(opsLimit), size_t(memLimit), crypto_pwhash_ALG_DEFAULT) != 0 {
            return nil
        }
        return output
    }

    public var scrypt = SCrypt()

    public class SCrypt {
        public let SaltBytes = Int(crypto_pwhash_scryptsalsa208sha256_saltbytes())
        public let StrBytes = Int(crypto_pwhash_scryptsalsa208sha256_strbytes()) - (1 as Int)
        public let StrPrefix = String(UTF8String: crypto_pwhash_scryptsalsa208sha256_strprefix())
        public let OpsLimitInteractive = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_interactive())
        public let OpsLimitSensitive = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive())
        public let MemLimitInteractive = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_interactive())
        public let MemLimitSensitive = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive())

        public func str(passwd: NSData, opsLimit: Int, memLimit: Int) -> String? {
            guard let output = NSMutableData(length: StrBytes) else {
                return nil
            }
            if crypto_pwhash_scryptsalsa208sha256_str(UnsafeMutablePointer<CChar>(output.mutableBytes), UnsafePointer<CChar>(passwd.bytes), CUnsignedLongLong(passwd.length), CUnsignedLongLong(opsLimit), size_t(memLimit)) != 0 {
                return nil
            }
            return NSString(data: output, encoding: NSUTF8StringEncoding) as String?
        }

        public func strVerify(hash: String, passwd: NSData) -> Bool {
            guard let hashData = (hash + "\0").dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) else {
                return false
            }
            return crypto_pwhash_scryptsalsa208sha256_str_verify(UnsafePointer<CChar>(hashData.bytes), UnsafePointer<CChar>(passwd.bytes), CUnsignedLongLong(passwd.length)) == 0
        }

        public func hash(outputLength: Int, passwd: NSData, salt: NSData, opsLimit: Int, memLimit: Int) -> NSData? {
            if salt.length != SaltBytes {
                return nil
            }
            guard let output = NSMutableData(length: outputLength) else {
                return nil
            }
            if crypto_pwhash_scryptsalsa208sha256(output.mutableBytesPtr, CUnsignedLongLong(outputLength), UnsafePointer<CChar>(passwd.bytes), CUnsignedLongLong(passwd.length), salt.bytesPtr, CUnsignedLongLong(opsLimit), size_t(memLimit)) != 0 {
                return nil
            }
            return output
        }
    }
}
