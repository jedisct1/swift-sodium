import Foundation
import Clibsodium

public class KeyExchange {
    public let PublicKeyBytes = Int(crypto_kx_publickeybytes())
    public let SecretKeyBytes = Int(crypto_kx_secretkeybytes())
    public let SessionKeyBytes = Int(crypto_kx_sessionkeybytes())
    public let SeedBytes = Int(crypto_kx_seedbytes())

    public typealias PublicKey = Data
    public typealias SecretKey = Data

    public struct KeyPair {
        public let publicKey: PublicKey
        public let secretKey: SecretKey

        public init(publicKey: PublicKey, secretKey: SecretKey) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }

    public struct SessionKeyPair {
        public let rx: Data
        public let tx: Data

        public init(rx: Data, tx: Data) {
            self.rx = rx
            self.tx = tx
        }
    }

    public enum Side {
        case CLIENT
        case SERVER

        var sessionKeys: (
            _ rx: UnsafeMutablePointer<UInt8>,
            _ tx: UnsafeMutablePointer<UInt8>,
            _ client_pk: UnsafePointer<UInt8>,
            _ client_sk: UnsafePointer<UInt8>,
            _ server_pk: UnsafePointer<UInt8>
        ) -> Int32 {
            switch self {
            case .CLIENT: return crypto_kx_client_session_keys
            case .SERVER: return crypto_kx_server_session_keys
            }
        }
    }

    /**
     Generates a key exchange secret key and a corresponding public key.

     - Returns: A key pair containing the secret key and public key.
     */
    public func keyPair() -> KeyPair? {
        var publicKey = Data(count: PublicKeyBytes)
        var secretKey = Data(count: SecretKeyBytes)

        guard .SUCCESS == publicKey.withUnsafeMutableBytes({ publicKeyPtr in
            secretKey.withUnsafeMutableBytes { secretKeyPtr in
                crypto_kx_keypair(publicKeyPtr, secretKeyPtr).exitCode
            }
        }) else { return nil }

        return KeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    /**
     Generates a key exchange secret key and a corresponding public key derived from a seed.

     - Parameter seed: The value from which to derive the secret and public key.

     - Returns: A key pair containing the secret key and public key.
     */
    public func keyPair(seed: Data) -> KeyPair? {
        guard seed.count == SeedBytes else { return nil }
        var pk = Data(count: PublicKeyBytes)
        var sk = Data(count: SecretKeyBytes)

        guard .SUCCESS == pk.withUnsafeMutableBytes({ pkPtr in
            sk.withUnsafeMutableBytes { skPtr in
                seed.withUnsafeBytes { seedPtr in
                    crypto_kx_seed_keypair(pkPtr, skPtr, seedPtr).exitCode
                }
            }
        }) else { return nil }

        return KeyPair(publicKey: pk, secretKey: sk)
    }

    /**
     Using this function, two parties can securely compute a set of shared keys using their peer's public key and their own secret key.
     See [libsodium.org/doc/key_exchange](https://download.libsodium.org/doc/key_exchange) for more details.

     - Parameter publicKey: The public key used for the key exchange
     - Parameter secretKey: The secret key to used for the key exchange
     - Parameter otherPublicKey: The peer's public key for the key exchange
     - Parameter side: Side (`client` or `host`) on which the key exchange is run

     - Returns: A `SessionKeyPair` consisting of a receive (`rx`) key and a transmit (`tx`) key

     - Note: `rx` on client side equals `tx` on server side and vice versa.
     */
    public func sessionKeyPair(publicKey: PublicKey, secretKey: SecretKey, otherPublicKey: PublicKey, side: Side) -> SessionKeyPair? {
        guard publicKey.count == PublicKeyBytes,
              secretKey.count == SecretKeyBytes,
              otherPublicKey.count == PublicKeyBytes
        else { return nil }

        var rx = Data(count: SessionKeyBytes)
        var tx = Data(count: SessionKeyBytes)

        guard .SUCCESS == rx.withUnsafeMutableBytes({ rxPtr in
            tx.withUnsafeMutableBytes { txPtr in
                secretKey.withUnsafeBytes { secretKeyPtr in
                    publicKey.withUnsafeBytes { publicKeyPtr in
                        otherPublicKey.withUnsafeBytes { otherPublicKeyPtr in
                            side.sessionKeys(rxPtr, txPtr, publicKeyPtr, secretKeyPtr, otherPublicKeyPtr).exitCode
                        }
                    }
                }
            }
        }) else { return nil }

        return SessionKeyPair(rx: rx, tx: tx)
    }
}
