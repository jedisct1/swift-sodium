import Foundation
import Clibsodium

public class KeyExchange {
    public let SessionKeyBytes = Int(crypto_kx_sessionkeybytes())

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

extension KeyExchange: KeyPairGenerator {
    public typealias PublicKey = Data
    public typealias SecretKey = Data

    public var SeedBytes: Int { return Int(crypto_kx_seedbytes()) }
    public var PublicKeyBytes: Int { return Int(crypto_kx_publickeybytes()) }
    public var SecretKeyBytes: Int { return Int(crypto_kx_secretkeybytes()) }

    static let newKeypair: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>
    ) -> Int32 = crypto_kx_keypair

    static let keypairFromSeed: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>,
        _ seed: UnsafePointer<UInt8>
    ) -> Int32 = crypto_kx_seed_keypair

    public struct KeyPair: KeyPairProtocol {
        public typealias PublicKey = KeyExchange.PublicKey
        public typealias SecretKey = KeyExchange.SecretKey
        public let publicKey: PublicKey
        public let secretKey: SecretKey
    }
}
