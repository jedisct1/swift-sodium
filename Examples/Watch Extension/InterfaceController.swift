//
//  InterfaceController.swift
//  Example Watch Extension
//
//  Created by Joseph Ross on 10/2/18.
//  Copyright © 2018 Frank Denis. All rights reserved.
//

import WatchKit
import Foundation
import Sodium


class InterfaceController: WKInterfaceController {

    override func awake(withContext context: Any?) {
        super.awake(withContext: context)
        
        let sodium = Sodium()
        let aliceKeyPair = sodium.box.keyPair()!
        let bobKeyPair = sodium.box.keyPair()!
        let message = "My Test Message".bytes
        
        print("Original Message:\(message.utf8String!)")
        
        let encryptedMessageFromAliceToBob: Bytes =
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
        
        print("Decrypted Message:\(messageVerifiedAndDecryptedByBob!.utf8String!)")
    }
    
    override func willActivate() {
        // This method is called when watch view controller is about to be visible to user
        super.willActivate()
    }
    
    override func didDeactivate() {
        // This method is called when watch view controller is no longer visible
        super.didDeactivate()
    }

}
