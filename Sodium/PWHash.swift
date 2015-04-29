//
//  PWHash.swift
//  Sodium
//
//  Created by Frank Denis on 4/29/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Foundation

public class PWHash {
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
            let output = NSMutableData(length: StrBytes)
            if output == nil {
                return nil
            }
            if crypto_pwhash_scryptsalsa208sha256_str(UnsafeMutablePointer<CChar>(output!.mutableBytes), UnsafePointer<CChar>(passwd.bytes), CUnsignedLongLong(passwd.length), CUnsignedLongLong(opsLimit), memLimit) != 0 {
                return nil
            }
            return NSString(data: output!, encoding: NSUTF8StringEncoding) as String?
        }

        public func strVerify(hash: String, passwd: NSData) -> Bool {
            let hashData = hash.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
            if hashData == nil {
                return false
            }
            return crypto_pwhash_scryptsalsa208sha256_str_verify(UnsafePointer<CChar>(hashData!.bytes), UnsafePointer<CChar>(passwd.bytes), CUnsignedLongLong(passwd.length)) == 0
        }
    }
}