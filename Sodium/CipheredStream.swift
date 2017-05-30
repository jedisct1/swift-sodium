//
//  CipheredStream.swift
//  Sodium
//
//  Created by WANG Jie on 29/05/2017.
//  Copyright © 2017 Frank Denis. All rights reserved.
//

import Foundation
import libsodium

public class CipheredStream {

    public func encrypts(message: Data, nonce: Data, key: Data) -> Data? {
        guard nonce.count == Int(crypto_stream_NONCEBYTES), key.count == Int(crypto_stream_KEYBYTES) else {
            return nil
        }
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count)
        guard crypto_stream_xor(buffer, [UInt8](message), UInt64(message.count), [UInt8](nonce), [UInt8](key)) == 0 else {
            return nil
        }
        return Data(bytes: buffer, count: message.count)
    }
}
