import Foundation

protocol KeyPairGenerator {
    associatedtype KeyPair: KeyPairProtocol

    var PublicKeyBytes: Int { get }
    associatedtype PublicKey where PublicKey == BytesContainer

    var SecretKeyBytes: Int { get }
    associatedtype SecretKey where SecretKey == BytesContainer

    var SeedBytes: Int { get }

    static var newKeypair: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>
    ) -> Int32 { get }

    static var keypairFromSeed: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>,
        _ seed: UnsafePointer<UInt8>
    ) -> Int32 { get }
}

extension KeyPairGenerator {
    /**
     Generates a signing secret key and a corresponding public key.

     - Returns: A key pair containing the secret key and public key.
     */
    public func keyPair() -> KeyPair? {
        var pk = BytesContainer(count: PublicKeyBytes)
        var sk = BytesContainer(count: SecretKeyBytes)

        guard .SUCCESS == Self.newKeypair(&pk.bytes, &sk.bytes).exitCode else { return nil }

        return KeyPair(publicKey: pk, secretKey: sk)
    }

    /**
     Generates a signing secret key and a corresponding public key derived from a seed.

     - Parameter seed: The value from which to derive the secret and public key.

     - Returns: A key pair containing the secret key and public key.
     */
    public func keyPair(seed: BytesRepresentable) -> KeyPair? {
        let seed = seed.bytes
        guard seed.count == SeedBytes else { return nil }
        var pk = BytesContainer(count: PublicKeyBytes)
        var sk = BytesContainer(count: SecretKeyBytes)

        guard .SUCCESS == Self.keypairFromSeed(&pk.bytes, &sk.bytes, seed).exitCode else {
            return nil
        }

        return KeyPair(publicKey: pk, secretKey: sk)
    }
}
