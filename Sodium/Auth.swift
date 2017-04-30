//
//  Auth.swift
//  Sodium
//
//  Created by WANG Jie on 03/04/2017.
//  Copyright © 2017 Frank Denis. All rights reserved.
//

import Foundation
import libsodium

public class Auth {
    public let authKeyBytes = Int(crypto_auth_KEYBYTES)
    
    public typealias AuthKey = Data

    public func authKey() -> AuthKey? {
        var ak = Data(count: authKeyBytes)
        ak.withUnsafeMutableBytes { akPtr in
            crypto_auth_keygen(akPtr)
        }
        return ak
    }

    public func sign(message: Data, authKey: AuthKey) -> Data? {
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: authKeyBytes)
        let result = crypto_auth(buffer, [UInt8](message), UInt64(message.count),  [UInt8](authKey))
        guard result == 0 else {
            return nil
        }
        return Data(bytes: buffer, count: authKeyBytes)
    }

    public func verify(message: Data, authKey: AuthKey, signature: Data) -> Bool {
        return crypto_auth_verify([UInt8](signature), [UInt8](message), UInt64(message.count), [UInt8](authKey)) == 0
    }
}
