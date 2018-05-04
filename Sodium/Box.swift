import Foundation
import Clibsodium

public struct Box {
    public let MacBytes = Int(crypto_box_macbytes())
    public let Primitive = String(validatingUTF8:crypto_box_primitive())
    public let BeforenmBytes = Int(crypto_box_beforenmbytes())
    public let SealBytes = Int(crypto_box_sealbytes())

    public typealias MAC = BytesContainer
    public typealias Beforenm = BytesContainer
}

extension Box {
    /**
     Encrypts a message with a recipient's public key and a sender's secret key.

     - Parameter message: The message to encrypt.
     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.

     - Returns: A `Bytes` object containing the nonce and authenticated ciphertext.
     */
    public func seal(message: BytesRepresentable, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> BytesContainer? {
        guard let (authenticatedCipherText, nonce): (BytesContainer, Nonce) = seal(message: message, recipientPublicKey: recipientPublicKey, senderSecretKey: senderSecretKey) else {
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
    public func seal(message: BytesRepresentable, recipientPublicKey: PublicKey, senderSecretKey: SecretKey, nonce: Nonce) -> BytesContainer? {
        guard recipientPublicKey.count == PublicKeyBytes,
            senderSecretKey.count == SecretKeyBytes,
            nonce.count == NonceBytes
        else { return nil }

        let message = message.bytes

        var authenticatedCipherText = BytesContainer(count: message.count + MacBytes)

        guard .SUCCESS == crypto_box_easy(
            &authenticatedCipherText.bytes,
            message, UInt64(message.count),
            nonce.bytes,
            recipientPublicKey.bytes,
            senderSecretKey.bytes
        ).exitCode else { return nil }

        return authenticatedCipherText
    }

    /**
     Encrypts a message with a recipient's public key and a sender's secret key.

     - Parameter message: The message to encrypt.
     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.

     - Returns: The authenticated ciphertext and encryption nonce.
     */
    public func seal(message: BytesRepresentable, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: BytesContainer, nonce: Nonce)? {
        guard recipientPublicKey.count == PublicKeyBytes,
              senderSecretKey.count == SecretKeyBytes
        else { return nil }

        let message = message.bytes

        var authenticatedCipherText = BytesContainer(count: message.count + MacBytes)
        let nonce = self.nonce()

        guard .SUCCESS == crypto_box_easy(
            &authenticatedCipherText.bytes,
            message, UInt64(message.count),
            nonce.bytes,
            recipientPublicKey.bytes,
            senderSecretKey.bytes
        ).exitCode else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    /**
     Encrypts a message with a recipient's public key and a sender's secret key (detached mode).

     - Parameter message: The message to encrypt.
     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.

     - Returns: The authenticated ciphertext, encryption nonce, and authentication tag.
     */
    public func seal(message: BytesRepresentable, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: BytesContainer, nonce: Nonce, mac: MAC)? {
        guard recipientPublicKey.count == PublicKeyBytes,
              senderSecretKey.count == SecretKeyBytes
        else { return nil }

        let message = message.bytes

        var authenticatedCipherText = BytesContainer(count: message.count)
        var mac = BytesContainer(count: MacBytes)
        let nonce = self.nonce()

        guard .SUCCESS == crypto_box_detached (
            &authenticatedCipherText.bytes,
            &mac.bytes,
            message, UInt64(message.count),
            nonce.bytes,
            recipientPublicKey.bytes,
            senderSecretKey.bytes
        ).exitCode else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce as Nonce, mac: mac as MAC)
    }

    /**
     Encrypts a message with the shared secret key generated from a recipient's public key and a sender's secret key using `beforenm()`.

     - Parameter message: The message to encrypt.
     - Parameter beforenm: The shared secret key.

     - Returns: The authenticated ciphertext and encryption nonce.
     */
    public func seal(message: BytesRepresentable, beforenm: Beforenm) -> (authenticatedCipherText: BytesContainer, nonce: Nonce)? {
        let message = message.bytes
        guard beforenm.count == BeforenmBytes else { return nil }
        var authenticatedCipherText = BytesContainer(count: message.count + MacBytes)
        let nonce = self.nonce()

        guard .SUCCESS == crypto_box_easy_afternm (
            &authenticatedCipherText.bytes,
            message, UInt64(message.count),
            nonce.bytes,
            beforenm.bytes
        ).exitCode else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    /**
     Encrypts a message with the shared secret key generated from a recipient's public key and a sender's secret key using `beforenm()`.

     - Parameter message: The message to encrypt.
     - Parameter beforenm: The shared secret key.

     - Returns: A `Bytes` object containing the encryption nonce and authenticated ciphertext.
     */
    public func seal(message: BytesRepresentable, beforenm: Beforenm) -> BytesContainer? {
        guard let (authenticatedCipherText, nonce): (BytesContainer, Nonce) = seal(
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
    public func seal(message: BytesRepresentable, recipientPublicKey: Box.PublicKey) -> BytesContainer? {
        guard recipientPublicKey.count == PublicKeyBytes else { return nil }
        let message = message.bytes
        var anonymousCipherText = BytesContainer(count: SealBytes + message.count)

        guard .SUCCESS == crypto_box_seal (
            &anonymousCipherText.bytes,
            message, UInt64(message.count),
            recipientPublicKey.bytes
        ).exitCode else { return nil }

        return anonymousCipherText
    }
}

extension Box {
    /**
     Decrypts a message with a sender's public key and the recipient's secret key.

     - Parameter nonceAndAuthenticatedCipherText: A `Bytes` object containing the nonce and authenticated ciphertext.
     - Parameter senderPublicKey: The sender's public key.
     - Parameter recipientSecretKey: The recipient's secret key.

     - Returns: The decrypted message.
     */
    public func open(nonceAndAuthenticatedCipherText: BytesRepresentable, senderPublicKey: PublicKey, recipientSecretKey: SecretKey) -> BytesContainer? {
        let nonceAndAuthenticatedCipherText = BytesContainer(nonceAndAuthenticatedCipherText)
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
    public func open(authenticatedCipherText: BytesRepresentable, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce) -> BytesContainer? {
        let authenticatedCipherText = authenticatedCipherText.bytes
        guard nonce.count == NonceBytes,
              authenticatedCipherText.count >= MacBytes,
              senderPublicKey.count == PublicKeyBytes,
              recipientSecretKey.count == SecretKeyBytes
        else { return nil }

        var message = BytesContainer(count: authenticatedCipherText.count - MacBytes)

        guard .SUCCESS == crypto_box_open_easy(
            &message.bytes,
            authenticatedCipherText, UInt64(authenticatedCipherText.count),
            nonce.bytes,
            senderPublicKey.bytes,
            recipientSecretKey.bytes
        ).exitCode else { return nil }

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
    public func open(authenticatedCipherText: BytesRepresentable, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce, mac: MAC) -> BytesContainer? {
        guard nonce.count == NonceBytes,
              mac.count == MacBytes,
              senderPublicKey.count == PublicKeyBytes,
              recipientSecretKey.count == SecretKeyBytes
        else { return nil }

        let authenticatedCipherText = authenticatedCipherText.bytes

        var message = BytesContainer(count: authenticatedCipherText.count)

        guard .SUCCESS == crypto_box_open_detached(
            &message.bytes,
            authenticatedCipherText,
            mac.bytes,
            UInt64(authenticatedCipherText.count),
            nonce.bytes,
            senderPublicKey.bytes,
            recipientSecretKey.bytes
        ).exitCode else { return nil }

        return message
    }

    /**
     Decrypts a message with the shared secret key generated from a recipient's public key and a sender's secret key using `beforenm()`.

     - Parameter nonceAndAuthenticatedCipherText: A `Bytes` object containing the nonce and authenticated ciphertext.
     - Parameter beforenm: The shared secret key.

     - Returns: The decrypted message.
     */
    public func open(nonceAndAuthenticatedCipherText: BytesRepresentable, beforenm: Beforenm) -> BytesContainer? {
        let nonceAndAuthenticatedCipherText = BytesContainer(nonceAndAuthenticatedCipherText)
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
    public func open(authenticatedCipherText: BytesRepresentable, beforenm: Beforenm, nonce: Nonce) -> BytesContainer? {
        let authenticatedCipherText = authenticatedCipherText.bytes
        guard nonce.count == NonceBytes,
              authenticatedCipherText.count >= MacBytes,
              beforenm.count == BeforenmBytes
        else { return nil }

        var message = BytesContainer(count: authenticatedCipherText.count - MacBytes)

        guard .SUCCESS == crypto_box_open_easy_afternm (
            &message.bytes,
            authenticatedCipherText, UInt64(authenticatedCipherText.count),
            nonce.bytes,
            beforenm.bytes
        ).exitCode else { return nil }

        return message
    }

    /**
     Decrypts a message with the recipient's public key and secret key.

     - Parameter anonymousCipherText: A `Bytes` object containing the anonymous ciphertext.
     - Parameter senderPublicKey: The recipient's public key.
     - Parameter recipientSecretKey: The recipient's secret key.

     - Returns: The decrypted message.
     */
    public func open(anonymousCipherText: BytesRepresentable, recipientPublicKey: PublicKey, recipientSecretKey: SecretKey) -> BytesContainer? {
        let anonymousCipherText = anonymousCipherText.bytes
        guard recipientPublicKey.count == PublicKeyBytes,
              recipientSecretKey.count == SecretKeyBytes,
              anonymousCipherText.count >= SealBytes
        else { return nil }

        var message = BytesContainer(count: anonymousCipherText.count - SealBytes)

        guard .SUCCESS == crypto_box_seal_open (
            &message.bytes,
            anonymousCipherText, UInt64(anonymousCipherText.count),
            recipientPublicKey.bytes,
            recipientSecretKey.bytes
        ).exitCode else { return nil }

        return message
    }
}

extension Box {
    /**
     Computes a shared secret key given a public key and a secret key.

     Applications that send several messages to the same receiver or receive several messages from the same sender can gain speed by calculating the shared key only once, and reusing it in subsequent operations.

     - Parameter recipientPublicKey: The recipient's public key.
     - Parameter senderSecretKey: The sender's secret key.

     - Returns: The computed shared secret key.
     */
    public func beforenm(recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> BytesContainer? {
        var key = BytesContainer(count: BeforenmBytes)
        guard .SUCCESS == crypto_box_beforenm (
            &key.bytes,
            recipientPublicKey.bytes,
            senderSecretKey.bytes
        ).exitCode else { return nil }

        return key
    }
}


extension Box: KeyPairGenerator {
    public typealias PublicKey = BytesContainer
    public typealias SecretKey = BytesContainer

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
    public typealias Nonce = BytesContainer

    public var NonceBytes: Int { return Int(crypto_box_noncebytes()) }
}
