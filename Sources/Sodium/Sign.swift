import Clibsodium
import Foundation

public struct Sign {
    public let Bytes = Int(crypto_sign_bytes())
    public let Primitive = String(validatingUTF8: crypto_sign_primitive())
}

public extension Sign {
    class Stream {
        private var state = crypto_sign_state()
        private var finalized = false

        init?() {
            guard crypto_sign_init(&state).exitCode == .SUCCESS else { return nil }
        }
    }
}

public extension Sign {
    /**
     Signs a message with the sender's secret key

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The sender's secret key.

     - Returns: The signed message.
     */
    func sign(message: Bytes, secretKey: SecretKey) -> Bytes? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signedMessage = [UInt8](count: message.count + Bytes)

        guard crypto_sign(
            &signedMessage,
            nil,
            message, UInt64(message.count),
            secretKey
        ).exitCode == .SUCCESS else { return nil }

        return signedMessage
    }

    /**
     Computes a detached signature for a message with the sender's secret key.

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The sender's secret key.

     - Returns: The computed signature.
     */
    func signature(message: Bytes, secretKey: SecretKey) -> Bytes? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var signature = [UInt8](count: Bytes)

        guard crypto_sign_detached(
            &signature,
            nil,
            message, UInt64(message.count),
            secretKey
        ).exitCode == .SUCCESS else { return nil }

        return signature
    }
}

public extension Sign {
    /**
     Verifies a signed message with the sender's public key.

     - Parameter signedMessage: The signed message to verify.
     - Parameter publicKey: The sender's public key.

     - Returns: `true` if verification is successful.
     */
    func verify(signedMessage: Bytes, publicKey: PublicKey) -> Bool {
        guard signedMessage.count >= Bytes else { return false }

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
    func verify(message: Bytes, publicKey: PublicKey, signature: Bytes) -> Bool {
        guard publicKey.count == PublicKeyBytes, signature.count == Bytes else {
            return false
        }

        return crypto_sign_verify_detached(
            signature,
            message, UInt64(message.count),
            publicKey
        ).exitCode == .SUCCESS
    }
}

public extension Sign {
    /**
     Extracts and returns the message data of a signed message if the signature is verified with the sender's secret key.

     - Parameter signedMessage: The signed message to open.
     - Parameter publicKey: The sender's public key.

     - Returns: The message data if verification is successful.
     */
    func open(signedMessage: Bytes, publicKey: PublicKey) -> Bytes? {
        guard publicKey.count == PublicKeyBytes, signedMessage.count >= Bytes else {
            return nil
        }

        var message = [UInt8](count: signedMessage.count - Bytes)
        var mlen: UInt64 = 0

        guard crypto_sign_open(
            &message, &mlen,
            signedMessage, UInt64(signedMessage.count),
            publicKey
        ).exitCode == .SUCCESS else { return nil }

        return message
    }
}

public extension Sign {
    /**
     Extracts the public key from a secret key.

     - Parameter secretKey: The secret key.

     - Returns: The public key.
     */
    func publicKey(secretKey: SecretKey) -> PublicKey? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var publicKey = [UInt8](count: PublicKeyBytes)

        guard crypto_sign_ed25519_sk_to_pk(
            &publicKey,
            secretKey
        ).exitCode == .SUCCESS else { return nil }

        return publicKey
    }

    /**
     Extracts the seed of a secret key.

     The seed is enough to recreate the key pair with `keyPair(seed:)`.

     - Parameter secretKey: The secret key.

     - Returns: The seed.
     */
    func seed(secretKey: SecretKey) -> Bytes? {
        guard secretKey.count == SecretKeyBytes else { return nil }
        var seed = [UInt8](count: SeedBytes)

        guard crypto_sign_ed25519_sk_to_seed(
            &seed,
            secretKey
        ).exitCode == .SUCCESS else { return nil }

        return seed
    }
}

public extension Sign {
    /**
     Initializes a `Stream` object to sign or verify a message piece by piece, such as a large file.

     Streams use a different algorithm (Ed25519ph) than `signature(message:secretKey:)`.
     A signature created by a stream can only be verified by a stream.

     - Returns: The initialized `Stream`.
     */
    func initStream() -> Stream? {
        Stream()
    }
}

public extension Sign.Stream {
    /**
     Adds the next part of the message to the stream.

     - Parameter input: The next part of the message.

     - Returns: `true` on success, or `false` if the stream was already finalized.
     */
    @discardableResult
    func update(input: Bytes) -> Bool {
        guard !finalized else { return false }

        return crypto_sign_update(
            &state,
            input, UInt64(input.count)
        ).exitCode == .SUCCESS
    }

    /**
     Signs the whole message, and finalizes the stream.

     - Parameter secretKey: The sender's secret key.

     - Returns: The signature, or `nil` if the stream was already finalized.
     A key with the wrong size also returns `nil`, but leaves the stream usable.
     */
    func final(secretKey: Sign.SecretKey) -> Bytes? {
        guard !finalized, secretKey.count == Int(crypto_sign_secretkeybytes()) else { return nil }
        finalized = true

        var signature = [UInt8](count: Int(crypto_sign_bytes()))

        guard crypto_sign_final_create(
            &state,
            &signature,
            nil,
            secretKey
        ).exitCode == .SUCCESS else { return nil }

        return signature
    }

    /**
     Verifies the signature of the whole message, and finalizes the stream.

     - Parameter publicKey: The sender's public key.
     - Parameter signature: A signature created by a stream.

     - Returns: `true` if the signature is valid.
     A key or signature with the wrong size returns `false`, but leaves the stream usable.
     */
    func verify(publicKey: Sign.PublicKey, signature: Bytes) -> Bool {
        guard !finalized,
              publicKey.count == Int(crypto_sign_publickeybytes()),
              signature.count == Int(crypto_sign_bytes())
        else { return false }
        finalized = true

        return crypto_sign_final_verify(
            &state,
            signature,
            publicKey
        ).exitCode == .SUCCESS
    }
}

extension Sign: KeyPairGenerator {
    public typealias PublicKey = Bytes
    public typealias SecretKey = Bytes

    public var SeedBytes: Int {
        Int(crypto_sign_seedbytes())
    }

    public var PublicKeyBytes: Int {
        Int(crypto_sign_publickeybytes())
    }

    public var SecretKeyBytes: Int {
        Int(crypto_sign_secretkeybytes())
    }

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
