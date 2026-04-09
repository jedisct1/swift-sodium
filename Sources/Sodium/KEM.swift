import Clibsodium

public struct KEM {
    public let Primitive = String(validatingUTF8: crypto_kem_primitive())
    public let CipherTextBytes = Int(crypto_kem_ciphertextbytes())
    public let SharedSecretBytes = Int(crypto_kem_sharedsecretbytes())
}

public extension KEM {
    /**
     Generates a shared secret and the corresponding ciphertext for a recipient.

     - Parameter recipientPublicKey: The recipient's public key.

     - Returns: A ciphertext to send to the recipient and the shared secret,
       or `nil` if `recipientPublicKey` is the wrong length.
     */
    func encapsulate(recipientPublicKey: PublicKey) -> (cipherText: Bytes, sharedSecret: Bytes)? {
        guard recipientPublicKey.count == PublicKeyBytes else { return nil }
        var cipherText = Bytes(count: CipherTextBytes)
        var sharedSecret = Bytes(count: SharedSecretBytes)
        guard crypto_kem_enc(&cipherText, &sharedSecret, recipientPublicKey)
            .exitCode == .SUCCESS else { return nil }
        return (cipherText: cipherText, sharedSecret: sharedSecret)
    }

    /**
     Recovers a shared secret from a ciphertext using the recipient's secret key.

     - Parameter cipherText: The ciphertext produced by `encapsulate`.
     - Parameter secretKey:  The recipient's secret key.

     - Returns: The shared secret, or `nil` if `cipherText` or `secretKey` is the
       wrong length. Note that a ciphertext of the correct length that has been
       tampered with will not cause a `nil` return — the underlying primitive uses
       implicit rejection and returns a pseudo-random key instead.
     */
    func decapsulate(cipherText: Bytes, secretKey: SecretKey) -> Bytes? {
        guard cipherText.count == CipherTextBytes,
              secretKey.count == SecretKeyBytes else { return nil }
        var sharedSecret = Bytes(count: SharedSecretBytes)
        guard crypto_kem_dec(&sharedSecret, cipherText, secretKey)
            .exitCode == .SUCCESS else { return nil }
        return sharedSecret
    }
}

extension KEM: KeyPairGenerator {
    public typealias PublicKey = Bytes
    public typealias SecretKey = Bytes

    public var PublicKeyBytes: Int {
        Int(crypto_kem_publickeybytes())
    }

    public var SecretKeyBytes: Int {
        Int(crypto_kem_secretkeybytes())
    }

    public var SeedBytes: Int {
        Int(crypto_kem_seedbytes())
    }

    public static let newKeypair: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>
    ) -> Int32 = crypto_kem_keypair

    public static let keypairFromSeed: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>,
        _ seed: UnsafePointer<UInt8>
    ) -> Int32 = crypto_kem_seed_keypair

    public struct KeyPair: KeyPairProtocol {
        public typealias PublicKey = KEM.PublicKey
        public typealias SecretKey = KEM.SecretKey
        public let publicKey: PublicKey
        public let secretKey: SecretKey

        public init(publicKey: PublicKey, secretKey: SecretKey) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }
}
