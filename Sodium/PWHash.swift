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
    public let StrPrefix = String.init(validatingUTF8: crypto_pwhash_strprefix())
    public let OpsLimitInteractive = Int(crypto_pwhash_opslimit_interactive())
    public let OpsLimitModerate = Int(crypto_pwhash_opslimit_moderate())
    public let OpsLimitSensitive = Int(crypto_pwhash_opslimit_sensitive())
    public let MemLimitInteractive = Int(crypto_pwhash_memlimit_interactive())
    public let MemLimitModerate = Int(crypto_pwhash_memlimit_moderate())
    public let MemLimitSensitive = Int(crypto_pwhash_memlimit_sensitive())

    public func str(passwd: Data, opsLimit: Int, memLimit: Int) -> String? {
        var output = Data(count: StrBytes)
        let result = output.withUnsafeMutableBytes { outputPtr in
            return passwd.withUnsafeBytes { passwdPtr in
                return crypto_pwhash_str(outputPtr,
                                         passwdPtr,
                                         CUnsignedLongLong(passwd.count),
                                         CUnsignedLongLong(opsLimit),
                                         size_t(memLimit))
            }
        }

        if result != 0 {
            return nil
        }

        return String(data: output, encoding: .utf8)
    }

    public func strVerify(hash: String, passwd: Data) -> Bool {
        guard let hashData = (hash + "\0").data(using: .utf8, allowLossyConversion: false) else {
                return false
        }

        return hashData.withUnsafeBytes { hashPtr in
            return passwd.withUnsafeBytes { passwdPtr in
                return crypto_pwhash_str_verify(
                  hashPtr,
                  passwdPtr,
                  CUnsignedLongLong(passwd.count)) == 0
            }
        }
    }

    public func hash(outputLength: Int, passwd: Data, salt: Data, opsLimit: Int, memLimit: Int) -> Data? {
        if salt.count != SaltBytes {
            return nil
        }

        var output = Data(count: outputLength)

        let result = passwd.withUnsafeBytes { passwdPtr in
            return salt.withUnsafeBytes { saltPtr in
                return output.withUnsafeMutableBytes { outputPtr in
                    return crypto_pwhash(
                      outputPtr,
                      CUnsignedLongLong(outputLength),
                      passwdPtr,
                      CUnsignedLongLong(passwd.count),
                      saltPtr,
                      CUnsignedLongLong(opsLimit),
                      size_t(memLimit),
                      crypto_pwhash_ALG_DEFAULT)
                }
            }
        }

        if result != 0 {
            return nil
        }

        return output
    }

    public var scrypt = SCrypt()

    public class SCrypt {
        public let SaltBytes = Int(crypto_pwhash_scryptsalsa208sha256_saltbytes())
        public let StrBytes = Int(crypto_pwhash_scryptsalsa208sha256_strbytes()) - (1 as Int)
        public let StrPrefix = String.init(validatingUTF8: crypto_pwhash_scryptsalsa208sha256_strprefix())
        public let OpsLimitInteractive = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_interactive())
        public let OpsLimitSensitive = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive())
        public let MemLimitInteractive = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_interactive())
        public let MemLimitSensitive = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive())

        public func str(passwd: Data, opsLimit: Int, memLimit: Int) -> String? {
            var output = Data(count: StrBytes)

            let result = output.withUnsafeMutableBytes { outputPtr in
                return passwd.withUnsafeBytes { passwdPtr in
                    crypto_pwhash_scryptsalsa208sha256_str(
                      outputPtr,
                      passwdPtr,
                      CUnsignedLongLong(passwd.count),
                      CUnsignedLongLong(opsLimit),
                      size_t(memLimit))
                }
            }

            if result != 0 {
                return nil
            }

            return String(data: output, encoding: .utf8)
        }

        public func strVerify(hash: String, passwd: Data) -> Bool {
            guard let hashData = (hash + "\0").data(using: .utf8, allowLossyConversion: false) else {
                return false
            }

            return hashData.withUnsafeBytes { hashDataPtr in
                return passwd.withUnsafeBytes { passwdPtr in
                    return crypto_pwhash_scryptsalsa208sha256_str_verify(
                      hashDataPtr,
                      passwdPtr,
                      CUnsignedLongLong(passwd.count)) == 0
                }
            }

        }

        public func hash(outputLength: Int, passwd: Data, salt: Data, opsLimit: Int, memLimit: Int) -> Data? {
            if salt.count != SaltBytes {
                return nil
            }

            var output = Data(count: outputLength)

            let result = output.withUnsafeMutableBytes { outputPtr in
                return passwd.withUnsafeBytes { passwdPtr in
                    return salt.withUnsafeBytes { saltPtr in
                        return crypto_pwhash_scryptsalsa208sha256(
                          outputPtr,
                          CUnsignedLongLong(outputLength),
                          passwdPtr,
                          CUnsignedLongLong(passwd.count),
                          saltPtr,
                          CUnsignedLongLong(opsLimit),
                          size_t(memLimit))
                    }
                }
            }

            if result != 0 {
                return nil
            }

            return output
        }
    }
}
