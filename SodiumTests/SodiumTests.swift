//
//  SodiumTests.swift
//  SodiumTests
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import XCTest
import Sodium

class SodiumTests: XCTestCase {
    let sodium = Sodium()
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testExample() {
        XCTAssert(true, "Pass")
        let sodium = Sodium()
        let kp = sodium.box.keyPair()
        let sealed: (NSData, Box.Nonce)? = sodium.box.seal("test".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!, recipientPublicKey: kp!.publicKey, senderSecretKey: kp!.secretKey)
        println(sealed)
    }
    
    func testPerformanceExample() {
        self.measureBlock() {
        }
    }
    
}
