//
//  Sodium.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

public class Sodium {
    public lazy var randomBytes: RandomBytes = RandomBytes()
    public lazy var genericHash: GenericHash = GenericHash()
    public lazy var utils: Utils = Utils()
    
    public init() {
        struct Once {
            static var once: dispatch_once_t = 0
        }
        dispatch_once(&Once.once) {
            sodium_init()
            ()
        }
    }    
}
