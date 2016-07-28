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
        
        print("Original Message:\(message.toString())")
        
        let encryptedMessageFromAliceToBob: NSData =
        sodium.box.seal(message,
            recipientPublicKey: bobKeyPair.publicKey,
            senderSecretKey: aliceKeyPair.secretKey)!
        
        print("Encrypted Message:\(encryptedMessageFromAliceToBob)")
        
        let messageVerifiedAndDecryptedByBob =
        sodium.box.open(encryptedMessageFromAliceToBob,
            senderPublicKey: bobKeyPair.publicKey,
            recipientSecretKey: aliceKeyPair.secretKey)
        
        print("Decrypted Message:\(messageVerifiedAndDecryptedByBob!.toString())")
        
        
        
        
        let key = String(count: 32, repeatedValue: Character("k")).dataUsingEncoding(NSUTF8StringEncoding)
        let iv =  String(count: 32, repeatedValue: Character("i")).dataUsingEncoding(NSUTF8StringEncoding)
        
        sodium.stream.initStream(key: key!, iv: iv!)
        
        let encrypted = sodium.stream.update(message)
        print("Encrypted with chacha20:\(encrypted)")
        
        let message2 = "hohohahi rezhewudi".dataUsingEncoding(NSUTF8StringEncoding)
        let encrypted2 = sodium.stream.update(message2!)
        print(encrypted2)
        
        let sodium2 = Sodium()!
        sodium2.stream.initStream(key: key!, iv: iv!)
        print("Decrypted chacha20:\(sodium2.stream.update(encrypted!)!.toString())")
        print("Decrypted chacha20:\(sodium2.stream.update(encrypted2!)!.toString())")
        
        
        sodium.stream.initStream(key: key!, iv: iv!)
        
        let encrypted_again = sodium.stream.update(message)
        print("Encrypted again with chacha20:\(encrypted_again)")
        
        
    }

    func applicationWillTerminate(aNotification: NSNotification) {
        // Insert code here to tear down your application
    }


}

