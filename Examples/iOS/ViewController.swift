import UIKit
import Sodium

class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()

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

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
    }
}

