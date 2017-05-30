//
//  CipheredStreamTest.swift
//  Sodium
//
//  Created by WANG Jie on 29/05/2017.
//  Copyright © 2017 Frank Denis. All rights reserved.
//

import XCTest
import Sodium

class CipheredStreamTest: XCTestCase {
    let sodium = Sodium()!

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testCipherdStream() {
        let nonce = sodium.randomBytes.buf(length: 24)!
        let key = sodium.randomBytes.buf(length: 32)!
        let message = "message"
        let cipheredStream = sodium.cipheredStream.encrypts(message: message.data(using: .utf8)!, nonce: nonce, key: key)!
        let plainStream = sodium.cipheredStream.encrypts(message: cipheredStream, nonce: nonce, key: key)
        XCTAssertEqual(message.data(using: .utf8), plainStream)
    }
}
