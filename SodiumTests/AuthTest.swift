//
//  AuthTest.swift
//  Sodium
//
//  Created by WANG Jie on 03/04/2017.
//  Copyright © 2017 Frank Denis. All rights reserved.
//

import XCTest
import Sodium

class AuthTest: XCTestCase {
    let authKey = "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
    let authMessage = "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5"
    let authHmacSha512256 = "b2a31b8d4e01afcab2ee545b5caf4e3d212a99d7b3a116a97cec8e83c32e107d"

    let sodium = Sodium()!

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSign() {
        let key = sodium.utils.hex2bin(authKey)!
        let mac = sodium.auth.sign(message: sodium.utils.hex2bin(authMessage)!, authKey: key)
        XCTAssertEqual(mac, sodium.utils.hex2bin(authHmacSha512256))
    }

    func testAuthKey() {
        let key = sodium.auth.authKey()!
        let mac = sodium.auth.sign(message: sodium.utils.hex2bin(authMessage)!, authKey: key)
        XCTAssertNotNil(mac)
    }

    func testVerify() {
        let signature = sodium.utils.hex2bin(authHmacSha512256)!
        let message = sodium.utils.hex2bin(authMessage)!
        let key = sodium.utils.hex2bin(authKey)!
        let result = sodium.auth.verify(message: message, authKey: key, signature: signature)
        XCTAssertTrue(result)
    }
}
