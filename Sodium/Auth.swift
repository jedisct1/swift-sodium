//
//  Auth.swift
//  Sodium
//
//  Created by WANG Jie on 03/04/2017.
//  Copyright © 2017 Frank Denis. All rights reserved.
//

import Foundation

public class Auth {
    public let authKeyBytes = Int(crypto_auth_KEYBYTES)
    
    public typealias AuthKey = Data

    public func authKey() -> AuthKey? {
        var ak = Data(count: authKeyBytes)
        return ak
    }

    public func sign(message: Data, authKey: AuthKey) -> Data? {
        return nil
    }

    public func verify(message: Data, authKey: AuthKey, signature: Data) -> Bool {
        return false
    }
}
