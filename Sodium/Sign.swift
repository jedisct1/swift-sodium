import Foundation
import Clibsodium

public struct Sign {
    public let Bytes = Int(crypto_sign_bytes())
    public let Primitive = String(validatingUTF8: crypto_sign_primitive())
}

extension Sign {
    /**
     Signs a message with the sender's secret key

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The sender's secret key.

     - Returns: The signed message.
     */
    public func sign(message: BytesRepresentable, secretKey: SecretKey) -> BytesContainer? {
        let message = message.bytes
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signedMessage = BytesContainer(count: message.count + Bytes)

        guard .SUCCESS == crypto_sign (
            &signedMessage.bytes,
            nil,
            message, UInt64(message.count),
            secretKey.bytes
        ).exitCode else { return nil }

        return signedMessage
    }

    /**
     Computes a detached signature for a message with the sender's secret key.

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The sender's secret key.

     - Returns: The computed signature.
     */
    public func signature(message: BytesRepresentable, secretKey: SecretKey) -> BytesContainer? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signature = BytesContainer(count: Bytes)

        let message = message.bytes
        guard .SUCCESS == crypto_sign_detached (
            &signature.bytes,
            nil,
            message, UInt64(message.count),
            secretKey.bytes
        ).exitCode else { return nil }

        return signature
    }
}

extension Sign {
    /**
     Verifies a signed message with the sender's public key.

     - Parameter signedMessage: The signed message to verify.
     - Parameter publicKey: The sender's public key.

     - Returns: `true` if verification is successful.
     */
    public func verify(signedMessage: BytesRepresentable, publicKey: PublicKey) -> Bool {
        let signedMessage = BytesContainer(signedMessage)
        let signature = signedMessage[..<Bytes]
        let message = signedMessage[Bytes...]

        return verify(message: message, publicKey: publicKey, signature: signature)
    }

    /**
     Verifies the detached signature of a message with the sender's public key.

     - Parameter message: The message to verify.
     - Parameter publicKey: The sender's public key.
     - Parameter signature: The detached signature to verify.

     - Returns: `true` if verification is successful.
     */
    public func verify(message: BytesRepresentable, publicKey: PublicKey, signature: BytesContainer) -> Bool {
        guard publicKey.count == PublicKeyBytes else {
            return false
        }

        let message = message.bytes
        return .SUCCESS == crypto_sign_verify_detached (
            signature.bytes,
            message, UInt64(message.count),
            publicKey.bytes
        ).exitCode
    }
}

extension Sign {
    /**
     Extracts and returns the message data of a signed message if the signature is verified with the sender's secret key.

     - Parameter signedMessage: The signed message to open.
     - Parameter publicKey: The sender's public key.

     - Returns: The message data if verification is successful.
     */
    public func open(signedMessage: BytesRepresentable, publicKey: PublicKey) -> BytesContainer? {
        let signedMessage = signedMessage.bytes
        guard publicKey.count == PublicKeyBytes, signedMessage.count >= Bytes else {
            return nil
        }

        var message = BytesContainer(count: signedMessage.count - Bytes)
        var mlen: UInt64 = 0

        guard .SUCCESS == crypto_sign_open (
            &message.bytes, &mlen,
            signedMessage, UInt64(signedMessage.count),
            publicKey.bytes
        ).exitCode else { return nil }

        return message
    }
}

extension Sign: KeyPairGenerator {
    public typealias PublicKey = BytesContainer
    public typealias SecretKey = BytesContainer

    public var SeedBytes: Int { return Int(crypto_sign_seedbytes()) }
    public var PublicKeyBytes: Int { return Int(crypto_sign_publickeybytes()) }
    public var SecretKeyBytes: Int { return Int(crypto_sign_secretkeybytes()) }

    static let newKeypair: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>
    ) -> Int32 = crypto_sign_keypair

    static let keypairFromSeed: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>,
        _ seed: UnsafePointer<UInt8>
    ) -> Int32 = crypto_sign_seed_keypair

    public struct KeyPair: KeyPairProtocol {
        public typealias PublicKey = Sign.PublicKey
        public typealias SecretKey = Sign.SecretKey
        public let publicKey: PublicKey
        public let secretKey: SecretKey
    }
}
