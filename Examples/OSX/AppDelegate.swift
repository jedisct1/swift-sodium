//
//  AppDelegate.swift
//  Example OSX
//
//  Created by RamaKrishna Mallireddy on 19/04/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Cocoa
import Sodium

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

    @IBOutlet weak var window: NSWindow!


    func applicationDidFinishLaunching(aNotification: NSNotification) {
        // Insert code here to initialize your application

        let sodium = Sodium()!
        let aliceKeyPair = sodium.box.keyPair()!
        let bobKeyPair = sodium.box.keyPair()!
        let message: NSData = "My Test Message".toData()!

        println("Original Message:\(message.toString())")

        let encryptedMessageFromAliceToBob: NSData =
        sodium.box.seal(message,
            recipientPublicKey: bobKeyPair.publicKey,
            senderSecretKey: aliceKeyPair.secretKey)!

        println("Encrypted Message:\(encryptedMessageFromAliceToBob)")

        let messageVerifiedAndDecryptedByBob =
        sodium.box.open(encryptedMessageFromAliceToBob,
            senderPublicKey: bobKeyPair.publicKey,
            recipientSecretKey: aliceKeyPair.secretKey)

        println("Decrypted Message:\(messageVerifiedAndDecryptedByBob!.toString())")

    }

    func applicationWillTerminate(aNotification: NSNotification) {
        // Insert code here to tear down your application
    }


}

