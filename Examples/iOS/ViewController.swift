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

        let sodium = Sodium()
        let aliceKeyPair = sodium.box.keyPair()!
        let bobKeyPair = sodium.box.keyPair()!
        let message = "My Test Message".toData()!

        print("Original Message:\(String(describing: message.toString()))")

        let encryptedMessageFromAliceToBob: Data =
            sodium.box.seal(
                message: message,
                recipientPublicKey: bobKeyPair.publicKey,
                senderSecretKey: aliceKeyPair.secretKey)!

        print("Encrypted Message:\(encryptedMessageFromAliceToBob)")

        let messageVerifiedAndDecryptedByBob =
            sodium.box.open(
                nonceAndAuthenticatedCipherText: encryptedMessageFromAliceToBob,
                senderPublicKey: bobKeyPair.publicKey,
                recipientSecretKey: aliceKeyPair.secretKey)

        print("Decrypted Message:\(String(describing: messageVerifiedAndDecryptedByBob!.toString()))")

    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

