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
    public func sign(message: Bytes, secretKey: SecretKey) -> Bytes? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signedMessage = Array<UInt8>(count: message.count + Bytes)

        guard .SUCCESS == crypto_sign (
            &signedMessage,
            nil,
            message, UInt64(message.count),
            secretKey
        ).exitCode else { return nil }

        return signedMessage
    }

    /**
     Computes a detached signature for a message with the sender's secret key.

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The sender's secret key.

     - Returns: The computed signature.
     */
    public func signature(message: Bytes, secretKey: SecretKey) -> Bytes? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signature = Array<UInt8>(count: Bytes)

        guard .SUCCESS == crypto_sign_detached (
            &signature,
            nil,
            message, UInt64(message.count),
            secretKey
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
    public func verify(signedMessage: Bytes, publicKey: PublicKey) -> Bool {
        let signature = signedMessage[..<Bytes].bytes
        let message = signedMessage[Bytes...].bytes

        return verify(message: message, publicKey: publicKey, signature: signature)
    }

    /**
     Verifies the detached signature of a message with the sender's public key.

     - Parameter message: The message to verify.
     - Parameter publicKey: The sender's public key.
     - Parameter signature: The detached signature to verify.

     - Returns: `true` if verification is successful.
     */
    public func verify(message: Bytes, publicKey: PublicKey, signature: Bytes) -> Bool {
        guard publicKey.count == PublicKeyBytes else {
            return false
        }

        return .SUCCESS == crypto_sign_verify_detached (
            signature,
            message, UInt64(message.count),
            publicKey
        ).exitCode
    }
}

extension Sign {
    /**
     Converts an Ed25519 public key used for signing into a Curve25519 public key usable for encryption.
     
     - Parameter publicKey: an Ed25519 public key generated from Sign.keyPair()
     
     - Returns: A Box.PublicKey is conversion succeeds, nil otherwise
    */
    public func convertEd25519PkToCurve25519(publicKey: PublicKey) -> Box.PublicKey? {
        var curve25519Bytes = Array<UInt8>(count: crypto_box_publickeybytes())
        
        if .SUCCESS == crypto_sign_ed25519_pk_to_curve25519(&curve25519Bytes, publicKey).exitCode {
            return Box.PublicKey(curve25519Bytes)
        } else {
            return nil
        }
    }
    
    /**
     Converts an Ed25519 secret key used for signing into a Curve25519 keypair usable for encryption.
     
     - Parameter publicKey: an Ed25519 secret key generated from Sign.keyPair()
     
     - Returns: A Box.SecretKey is conversion succeeds, nil otherwise
     */
    public func convertEd25519SkToCurve25519(secretKey: SecretKey) -> Box.SecretKey? {
        var curve25519Bytes = Array<UInt8>(count: crypto_box_secretkeybytes())
        
        if .SUCCESS == crypto_sign_ed25519_sk_to_curve25519(&curve25519Bytes, secretKey).exitCode {
            return Box.SecretKey(curve25519Bytes)
        }
        else {
            return nil
        }
    }
    
    /**
     Converts an Ed25519 Sign.KeyPair into a Curve25519 Box.KeyPair.  This is a convenience method
     for calling convertEd25519PkToCurve25519 and convertEd25519SkToCurve25519 individually.
     
     - Parameter keyPair: A Sign.KeyPair generated from Sign.KeyPair()
     
     - Returns: a Box.KeyPair, nil if either key conversion fails
     */
    public func convertEd25519KeyPairToCurve25519(keyPair: KeyPair) -> Box.KeyPair? {
        let publicKeyResult = convertEd25519PkToCurve25519(publicKey: keyPair.publicKey)
        let secretKeyResult = convertEd25519SkToCurve25519(secretKey: keyPair.secretKey)
        
        if let publicKey = publicKeyResult, let secretKey = secretKeyResult {
            return Box.KeyPair(publicKey: publicKey, secretKey: secretKey)
        }
        else {
            return nil;
        }
    }
}

extension Sign {
    /**
     Extracts and returns the message data of a signed message if the signature is verified with the sender's secret key.

     - Parameter signedMessage: The signed message to open.
     - Parameter publicKey: The sender's public key.

     - Returns: The message data if verification is successful.
     */
    public func open(signedMessage: Bytes, publicKey: PublicKey) -> Bytes? {
        guard publicKey.count == PublicKeyBytes, signedMessage.count >= Bytes else {
            return nil
        }

        var message = Array<UInt8>(count: signedMessage.count - Bytes)
        var mlen: UInt64 = 0

        guard .SUCCESS == crypto_sign_open (
            &message, &mlen,
            signedMessage, UInt64(signedMessage.count),
            publicKey
        ).exitCode else { return nil }

        return message
    }
}

extension Sign: KeyPairGenerator {
    public typealias PublicKey = Bytes
    public typealias SecretKey = Bytes

    public var SeedBytes: Int { return Int(crypto_sign_seedbytes()) }
    public var PublicKeyBytes: Int { return Int(crypto_sign_publickeybytes()) }
    public var SecretKeyBytes: Int { return Int(crypto_sign_secretkeybytes()) }

    public static let newKeypair: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>
    ) -> Int32 = crypto_sign_keypair

    public static let keypairFromSeed: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>,
        _ seed: UnsafePointer<UInt8>
    ) -> Int32 = crypto_sign_seed_keypair

    public struct KeyPair: KeyPairProtocol {
        public typealias PublicKey = Sign.PublicKey
        public typealias SecretKey = Sign.SecretKey
        public let publicKey: PublicKey
        public let secretKey: SecretKey

        public init(publicKey: PublicKey, secretKey: SecretKey) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }
}
