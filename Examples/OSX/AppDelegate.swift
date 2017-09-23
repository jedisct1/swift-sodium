import Cocoa
import Sodium

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
    @IBOutlet weak var window: NSWindow!

    func applicationDidFinishLaunching(aNotification: NSNotification) {
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

    func applicationWillTerminate(aNotification: NSNotification) {

    }
}

