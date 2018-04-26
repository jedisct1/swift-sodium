import Foundation
import Clibsodium

public class Box {
    public let MacBytes = Int(crypto_box_macbytes())
    public let Primitive = String(validatingUTF8:crypto_box_primitive())
    public let BeforenmBytes = Int(crypto_box_beforenmbytes())
    public let SealBytes = Int(crypto_box_sealbytes())

    public typealias MAC = Data
    public typealias Beforenm = Data

    /**
     Encrypts a message with a recipient's public key and a sender's secret key.

     - Parameter message: The message to encrypt.
     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.

     - Returns: A `Data` object containing the nonce and authenticated ciphertext.
     */
    public func seal(message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> Data? {
        guard let (authenticatedCipherText, nonce): (Data, Nonce) = seal(message: message, recipientPublicKey: recipientPublicKey, senderSecretKey: senderSecretKey) else {
            return nil
        }
        return nonce + authenticatedCipherText
    }

    /**
     Encrypts a message with a recipient's public key and a sender's secret key using a user-provided nonce.

     - Parameter message: The message to encrypt.
     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.
     - Parameter nonce: The user-specified nonce.

     - Returns: The authenticated ciphertext.
     */
    public func seal(message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey, nonce: Nonce) -> Data? {
        guard recipientPublicKey.count == PublicKeyBytes,
            senderSecretKey.count == SecretKeyBytes,
            nonce.count == NonceBytes
        else { return nil }

        var authenticatedCipherText = Data(count: message.count + MacBytes)

        guard .SUCCESS == authenticatedCipherText.withUnsafeMutableBytes({ authenticatedCipherTextPtr in
            message.withUnsafeBytes { messagePtr in
                nonce.withUnsafeBytes { noncePtr in
                    recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                        senderSecretKey.withUnsafeBytes { senderSecretKeyPtr in
                            crypto_box_easy(
                                authenticatedCipherTextPtr,
                                messagePtr, CUnsignedLongLong(message.count),
                                noncePtr,
                                recipientPublicKeyPtr, senderSecretKeyPtr).exitCode
                        }
                    }
                }
            }
        }) else { return nil }

        return authenticatedCipherText
    }

    /**
     Encrypts a message with a recipient's public key and a sender's secret key.

     - Parameter message: The message to encrypt.
     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.

     - Returns: The authenticated ciphertext and encryption nonce.
     */
    public func seal(message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: Data, nonce: Nonce)? {
        guard recipientPublicKey.count == PublicKeyBytes,
              senderSecretKey.count == SecretKeyBytes
        else { return nil }

        var authenticatedCipherText = Data(count: message.count + MacBytes)
        let nonce = self.nonce()

        guard .SUCCESS == authenticatedCipherText.withUnsafeMutableBytes({ authenticatedCipherTextPtr in
            message.withUnsafeBytes { messagePtr in
                nonce.withUnsafeBytes { noncePtr in
                    recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                        senderSecretKey.withUnsafeBytes { senderSecretKeyPtr in
                            crypto_box_easy(
                                authenticatedCipherTextPtr,
                                messagePtr, CUnsignedLongLong(message.count),
                                noncePtr,
                                recipientPublicKeyPtr, senderSecretKeyPtr).exitCode
                        }
                    }
                }
            }
        }) else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    /**
     Encrypts a message with a recipient's public key and a sender's secret key (detached mode).

     - Parameter message: The message to encrypt.
     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.

     - Returns: The authenticated ciphertext, encryption nonce, and authentication tag.
     */
    public func seal(message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: Data, nonce: Nonce, mac: MAC)? {
        guard recipientPublicKey.count == PublicKeyBytes,
              senderSecretKey.count == SecretKeyBytes
        else { return nil }

        var authenticatedCipherText = Data(count: message.count)
        var mac = Data(count: MacBytes)
        let nonce = self.nonce()
        guard .SUCCESS == authenticatedCipherText.withUnsafeMutableBytes({ authenticatedCipherTextPtr in
            mac.withUnsafeMutableBytes { macPtr in
                message.withUnsafeBytes { messagePtr in
                    nonce.withUnsafeBytes { noncePtr in
                        recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                            senderSecretKey.withUnsafeBytes { senderSecretKeyPtr in
                                crypto_box_detached(
                                    authenticatedCipherTextPtr, macPtr,
                                    messagePtr, CUnsignedLongLong(message.count),
                                    noncePtr,
                                    recipientPublicKeyPtr, senderSecretKeyPtr).exitCode
                            }
                        }
                    }
                }
            }
        }) else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce as Nonce, mac: mac as MAC)
    }

    /**
     Decrypts a message with a sender's public key and the recipient's secret key.

     - Parameter nonceAndAuthenticatedCipherText: A `Data` object containing the nonce and authenticated ciphertext.
     - Parameter senderPublicKey: The sender's public key.
     - Parameter recipientSecretKey: The recipient's secret key.

     - Returns: The decrypted message.
     */
    public func open(nonceAndAuthenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey) -> Data? {
        guard nonceAndAuthenticatedCipherText.count >= NonceBytes + MacBytes else { return nil }
        let nonce = nonceAndAuthenticatedCipherText[..<NonceBytes] as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText[NonceBytes...]

        return open(authenticatedCipherText: authenticatedCipherText, senderPublicKey: senderPublicKey, recipientSecretKey: recipientSecretKey, nonce: nonce)
    }

    /**
     Decrypts a message with a sender's public key, recipient's secret key, and encryption nonce.

     - Parameter authenticatedCipherText: The authenticated ciphertext.
     - Parameter senderPublicKey: The sender's public key.
     - Parameter recipientSecretKey: The recipient's secret key.
     - Parameter nonce: The encryption nonce.

     - Returns: The decrypted message.
     */
    public func open(authenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce) -> Data? {
        guard nonce.count == NonceBytes,
              authenticatedCipherText.count >= MacBytes,
              senderPublicKey.count == PublicKeyBytes,
              recipientSecretKey.count == SecretKeyBytes
        else { return nil }

        var message = Data(count: authenticatedCipherText.count - MacBytes)
        guard .SUCCESS == message.withUnsafeMutableBytes({ messagePtr in
            authenticatedCipherText.withUnsafeBytes { authenticatedCipherTextPtr in
                nonce.withUnsafeBytes { noncePtr in
                    senderPublicKey.withUnsafeBytes { senderPublicKeyPtr in
                        recipientSecretKey.withUnsafeBytes { recipientSecretKeyPtr in
                            crypto_box_open_easy(
                                messagePtr, authenticatedCipherTextPtr,
                                CUnsignedLongLong(authenticatedCipherText.count),
                                noncePtr,
                                senderPublicKeyPtr, recipientSecretKeyPtr).exitCode
                        }
                    }
                }
            }
        }) else { return nil }

        return message
    }

    /**
     Decrypts a message with a sender's public key, recipient's secret key, encryption nonce, and authentication tag.

     - Parameter authenticatedCipherText: The authenticated ciphertext.
     - Parameter senderPublicKey: The sender's public key.
     - Parameter recipientSecretKey: The recipient's secret key.
     - Parameter nonce: The encryption nonce.
     - Parameter mac: The authentication tag.

     - Returns: The decrypted message.
     */
    public func open(authenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce, mac: MAC) -> Data? {
        guard nonce.count == NonceBytes,
              mac.count == MacBytes,
              senderPublicKey.count == PublicKeyBytes,
              recipientSecretKey.count == SecretKeyBytes
        else { return nil }

        var message = Data(count: authenticatedCipherText.count)

        guard .SUCCESS == message.withUnsafeMutableBytes({ messagePtr in
            authenticatedCipherText.withUnsafeBytes { authenticatedCipherTextPtr in
                mac.withUnsafeBytes { macPtr in
                    nonce.withUnsafeBytes { noncePtr in
                        senderPublicKey.withUnsafeBytes { senderPublicKeyPtr in
                            recipientSecretKey.withUnsafeBytes { recipientSecretKeyPtr in
                                crypto_box_open_detached(
                                    messagePtr, authenticatedCipherTextPtr, macPtr,
                                    CUnsignedLongLong(authenticatedCipherText.count),
                                    noncePtr,
                                    senderPublicKeyPtr, recipientSecretKeyPtr).exitCode
                            }
                        }
                    }
                }
            }
        }) else { return nil }

        return message
    }

    /**
     Computes a shared secret key given a public key and a secret key.

     Applications that send several messages to the same receiver or receive several messages from the same sender can gain speed by calculating the shared key only once, and reusing it in subsequent operations.

     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.

     - Returns: The computed shared secret key.
     */
    public func beforenm(recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> Data? {
        var key = Data(count: BeforenmBytes)
        guard .SUCCESS == key.withUnsafeMutableBytes({ keyPtr in
            recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                senderSecretKey.withUnsafeBytes { senderSecretKeyPtr in
                    crypto_box_beforenm(keyPtr, recipientPublicKeyPtr, senderSecretKeyPtr).exitCode
                }
            }
        }) else { return nil }

        return key
    }

    /**
     Encrypts a message with the shared secret key generated from a recipient's public key and a sender's secret key using `beforenm()`.

     - Parameter message: The message to encrypt.
     - Parameter beforenm: The shared secret key.

     - Returns: The authenticated ciphertext and encryption nonce.
     */
    public func seal(message: Data, beforenm: Beforenm) -> (authenticatedCipherText: Data, nonce: Nonce)? {
        guard beforenm.count == BeforenmBytes else { return nil }
        var authenticatedCipherText = Data(count: message.count + MacBytes)
        let nonce = self.nonce()

        guard .SUCCESS == authenticatedCipherText.withUnsafeMutableBytes({ authenticatedCipherTextPtr in
            message.withUnsafeBytes { messagePtr in
                nonce.withUnsafeBytes { noncePtr in
                    beforenm.withUnsafeBytes { beforenmPtr in
                        crypto_box_easy_afternm(
                            authenticatedCipherTextPtr,
                            messagePtr,
                            CUnsignedLongLong(message.count),
                            noncePtr,
                            beforenmPtr).exitCode
                    }
                }
            }
        }) else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    /**
     Decrypts a message with the shared secret key generated from a recipient's public key and a sender's secret key using `beforenm()`.

     - Parameter nonceAndAuthenticatedCipherText: A `Data` object containing the nonce and authenticated ciphertext.
     - Parameter beforenm: The shared secret key.

     - Returns: The decrypted message.
     */
    public func open(nonceAndAuthenticatedCipherText: Data, beforenm: Beforenm) -> Data? {
        guard nonceAndAuthenticatedCipherText.count >= NonceBytes + MacBytes else { return nil }

        let nonce = nonceAndAuthenticatedCipherText[..<NonceBytes] as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText[NonceBytes...]

        return  open(authenticatedCipherText: authenticatedCipherText, beforenm: beforenm, nonce: nonce)
    }

    /**
     Decrypts a message and encryption nonce with the shared secret key generated from a recipient's public key and a sender's secret key using `beforenm()`.

     - Parameter authenticatedCipherText: The authenticated ciphertext.
     - Parameter beforenm: The shared secret key.
     - Parameter nonce: The encryption nonce.

     - Returns: The decrypted message.
     */
    public func open(authenticatedCipherText: Data, beforenm: Beforenm, nonce: Nonce) -> Data? {
        guard nonce.count == NonceBytes,
              authenticatedCipherText.count >= MacBytes,
              beforenm.count == BeforenmBytes
        else { return nil }

        var message = Data(count: authenticatedCipherText.count - MacBytes)
        guard .SUCCESS == message.withUnsafeMutableBytes({ messagePtr in
            authenticatedCipherText.withUnsafeBytes { authenticatedCipherTextPtr in
                nonce.withUnsafeBytes { noncePtr in
                    beforenm.withUnsafeBytes { beforenmPtr in
                        crypto_box_open_easy_afternm(
                            messagePtr,
                            authenticatedCipherTextPtr, CUnsignedLongLong(authenticatedCipherText.count),
                            noncePtr, beforenmPtr).exitCode
                    }
                }
            }
        }) else { return nil }

        return message
    }

    /**
     Encrypts a message with the shared secret key generated from a recipient's public key and a sender's secret key using `beforenm()`.

     - Parameter message: The message to encrypt.
     - Parameter beforenm: The shared secret key.

     - Returns: A `Data` object containing the encryption nonce and authenticated ciphertext.
     */
    public func seal(message: Data, beforenm: Beforenm) -> Data? {
        guard let (authenticatedCipherText, nonce): (Data, Nonce) = seal(
            message: message,
            beforenm: beforenm
        ) else { return nil }

        return nonce + authenticatedCipherText
    }

    /**
     Encrypts a message with a recipient's public key.

     - Parameter message: The message to encrypt.
     - Parameter recipientPublicKey: The recipient's public key.

     - Returns: The anonymous ciphertext.
     */
    public func seal(message: Data, recipientPublicKey: Box.PublicKey) -> Data? {
        guard recipientPublicKey.count == PublicKeyBytes else { return nil }
        var anonymousCipherText = Data(count: SealBytes + message.count)

        guard .SUCCESS == anonymousCipherText.withUnsafeMutableBytes({ anonymousCipherTextPtr in
            message.withUnsafeBytes { messagePtr in
                recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                    crypto_box_seal(
                        anonymousCipherTextPtr,
                        messagePtr, CUnsignedLongLong(message.count),
                        recipientPublicKeyPtr).exitCode
                }
            }
        }) else { return nil }

        return anonymousCipherText
    }

    /**
     Decrypts a message with the recipient's public key and secret key.

     - Parameter anonymousCipherText: A `Data` object containing the anonymous ciphertext.
     - Parameter senderPublicKey: The recipient's public key.
     - Parameter recipientSecretKey: The recipient's secret key.

     - Returns: The decrypted message.
     */
    public func open(anonymousCipherText: Data, recipientPublicKey: PublicKey, recipientSecretKey: SecretKey) -> Data? {
        guard recipientPublicKey.count == PublicKeyBytes,
              recipientSecretKey.count == SecretKeyBytes,
              anonymousCipherText.count >= SealBytes
        else { return nil }

        var message = Data(count: anonymousCipherText.count - SealBytes)

        guard .SUCCESS == message.withUnsafeMutableBytes({ messagePtr in
            anonymousCipherText.withUnsafeBytes { anonymousCipherTextPtr in
                recipientPublicKey.withUnsafeBytes { recipientPublicKeyPtr in
                    recipientSecretKey.withUnsafeBytes { recipientSecretKeyPtr in
                        crypto_box_seal_open(
                            messagePtr,
                            anonymousCipherTextPtr, CUnsignedLongLong(anonymousCipherText.count),
                            recipientPublicKeyPtr, recipientSecretKeyPtr).exitCode
                    }
                }
            }
        }) else { return nil }

        return message
    }
}

extension Box: KeyPairGenerator {
    public typealias PublicKey = Data
    public typealias SecretKey = Data

    public var SeedBytes: Int { return Int(crypto_box_seedbytes()) }
    public var PublicKeyBytes: Int { return Int(crypto_box_publickeybytes()) }
    public var SecretKeyBytes: Int { return Int(crypto_box_secretkeybytes()) }

    static let newKeypair: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>
    ) -> Int32 = crypto_box_keypair

    static let keypairFromSeed: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>,
        _ seed: UnsafePointer<UInt8>
    ) -> Int32 = crypto_box_seed_keypair

    public struct KeyPair: KeyPairProtocol {
        public typealias PublicKey = Box.PublicKey
        public typealias SecretKey = Box.SecretKey
        public let publicKey: PublicKey
        public let secretKey: SecretKey
    }
}

extension Box: NonceGenerator {
    public typealias Nonce = Data

    public var NonceBytes: Int { return Int(crypto_box_noncebytes()) }
}
