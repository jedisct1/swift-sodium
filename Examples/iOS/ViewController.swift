//
//  ViewController.swift
//  Example iOS
//
//  Created by RamaKrishna Mallireddy on 19/04/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import UIKit
import Sodium

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.

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

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

