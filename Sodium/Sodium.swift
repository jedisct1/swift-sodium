//
//  Sodium.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class Sodium {
    public var box = Box()
    public var secretBox = SecretBox()
    public var genericHash = GenericHash()
    public var pwHash = PWHash()
    public var randomBytes = RandomBytes()
    public var shortHash = ShortHash()
    public var sign = Sign()
    public var utils = Utils()
    
    public init?() {
        struct Once {
            static var once: dispatch_once_t = 0
        }
        dispatch_once(&Once.once) {
            if sodium_init() == -1 {
                abort()
            }
            ()
        }
    }    
}
