//
//  Sodium.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation
import libsodium

public class Sodium {
    public let box = Box()
    public let secretBox = SecretBox()
    public let genericHash = GenericHash()
    public let pwHash = PWHash()
    public let randomBytes = RandomBytes()
    public let shortHash = ShortHash()
    public let sign = Sign()
    public let utils = Utils()
    public let keyExchange = KeyExchange()
    public let auth = Auth()
    public let stream = Stream()
	public let keyDerivation = KeyDerivation()

    public init?() {
        struct Once {
            static var once : () = {
                if sodium_init() == -1 {
                    abort()
                }
            }()
        }
    }
}
