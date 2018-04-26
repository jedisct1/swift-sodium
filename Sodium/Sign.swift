import Foundation
import Clibsodium

public class Sign {
    public let Bytes = Int(crypto_sign_bytes())
    public let Primitive = String(validatingUTF8: crypto_sign_primitive())

    /**
     Signs a message with the sender's secret key

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The sender's secret key.

     - Returns: The signed message.
     */
    public func sign(message: Data, secretKey: SecretKey) -> Data? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signedMessage = Data(count: message.count + Bytes)

        guard .SUCCESS == signedMessage.withUnsafeMutableBytes({ signedMessagePtr in
            message.withUnsafeBytes { messagePtr in
                secretKey.withUnsafeBytes { secretKeyPtr in
                    crypto_sign(
                        signedMessagePtr, nil,
                        messagePtr, CUnsignedLongLong(message.count),
                        secretKeyPtr).exitCode
                }
            }
        }) else { return nil }

        return signedMessage
    }

    /**
     Computes a detached signature for a message with the sender's secret key.

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The sender's secret key.

     - Returns: The computed signature.
     */
    public func signature(message: Data, secretKey: SecretKey) -> Data? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signature = Data(count: Bytes)

        guard .SUCCESS == signature.withUnsafeMutableBytes({ signaturePtr in
            message.withUnsafeBytes { messagePtr in
                secretKey.withUnsafeBytes { secretKeyPtr in
                    crypto_sign_detached(
                        signaturePtr, nil,
                        messagePtr, CUnsignedLongLong(message.count),
                        secretKeyPtr).exitCode
                }
            }
        }) else { return nil }

        return signature
    }

    /**
     Verifies a signed message with the sender's public key.

     - Parameter signedMessage: The signed message to verify.
     - Parameter publicKey: The sender's public key.

     - Returns: `true` if verification is successful.
     */
    public func verify(signedMessage: Data, publicKey: PublicKey) -> Bool {
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
    public func verify(message: Data, publicKey: PublicKey, signature: Data) -> Bool {
        guard publicKey.count == PublicKeyBytes else {
            return false
        }

        return .SUCCESS == signature.withUnsafeBytes { signaturePtr in
            message.withUnsafeBytes { messagePtr in
                publicKey.withUnsafeBytes { publicKeyPtr in
                    crypto_sign_verify_detached(
                        signaturePtr,
                        messagePtr, CUnsignedLongLong(message.count), publicKeyPtr).exitCode
                }
            }
        }
    }

    /**
     Extracts and returns the message data of a signed message if the signature is verified with the sender's secret key.

     - Parameter signedMessage: The signed message to open.
     - Parameter publicKey: The sender's public key.

     - Returns: The message data if verification is successful.
     */
    public func open(signedMessage: Data, publicKey: PublicKey) -> Data? {
        guard publicKey.count == PublicKeyBytes, signedMessage.count >= Bytes else {
            return nil
        }

        var message = Data(count: signedMessage.count - Bytes)
        var mlen: CUnsignedLongLong = 0

        guard .SUCCESS == message.withUnsafeMutableBytes({ messagePtr in
            signedMessage.withUnsafeBytes { signedMessagePtr in
                publicKey.withUnsafeBytes { publicKeyPtr in
                    crypto_sign_open(
                        messagePtr, &mlen,
                        signedMessagePtr, CUnsignedLongLong(signedMessage.count),
                        publicKeyPtr).exitCode
                }
            }
        }) else { return nil }

        return message
    }
}

extension Sign: KeyPairGenerator {
    public typealias PublicKey = Data
    public typealias SecretKey = Data

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
