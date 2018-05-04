import Foundation
import Clibsodium

public struct KeyExchange {
    public let SessionKeyBytes = Int(crypto_kx_sessionkeybytes())
}

extension KeyExchange {
    public struct SessionKeyPair {
        public let rx: BytesContainer
        public let tx: BytesContainer

        public init(rx: BytesContainer, tx: BytesContainer) {
            self.rx = rx
            self.tx = tx
        }
    }
}

extension KeyExchange {
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
}

extension KeyExchange {
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

        var rx = BytesContainer(count: SessionKeyBytes)
        var tx = BytesContainer(count: SessionKeyBytes)

        guard .SUCCESS == side.sessionKeys (
            &rx.bytes,
            &tx.bytes,
            publicKey.bytes,
            secretKey.bytes,
            otherPublicKey.bytes
        ).exitCode else { return nil }

        return SessionKeyPair(rx: rx, tx: tx)
    }
}

extension KeyExchange: KeyPairGenerator {
    public typealias PublicKey = BytesContainer
    public typealias SecretKey = BytesContainer

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
