import Foundation
import Clibsodium

public struct Auth {
    public let Bytes = Int(crypto_auth_bytes())
    public typealias SecretKey = Key
}

extension Auth {
    /**
     Computes an authentication tag for a message using a key

     - Parameter message: The message to authenticate.
     - Parameter secretKey: The key required to create and verify messages.

     - Returns: The computed authentication tag.
     */
    public func tag(message: BytesRepresentable, secretKey: SecretKey) -> BytesContainer? {
        guard secretKey.count == KeyBytes else { return nil }

        let message = message.bytes
        var tag = BytesContainer(count: Bytes)
        guard .SUCCESS == crypto_auth (
            &tag.bytes,
            message, UInt64(message.count),
            secretKey.bytes
        ).exitCode else { return nil }

        return tag
    }

    /**
     Verifies that an authentication tag is valid for a message and a key

     - Parameter message: The message to verify.
     - Parameter secretKey: The key required to create and verify messages.
     - Parameter tag: The authentication tag.

     - Returns: `true` if the verification is successful.
     */
    public func verify(message: BytesRepresentable, secretKey: SecretKey, tag: BytesRepresentable) -> Bool {
        guard secretKey.count == KeyBytes else {
            return false
        }
        let (tag, message) = (tag.bytes, message.bytes)
        return .SUCCESS == crypto_auth_verify (
            tag,
            message, UInt64(message.count),
            secretKey.bytes
        ).exitCode
    }
}

extension Auth: SecretKeyGenerator {
    public var KeyBytes: Int { return Int(crypto_auth_keybytes()) }
    public typealias Key = BytesContainer

    static let keygen: (_ k: UnsafeMutablePointer<UInt8>) -> Void = crypto_auth_keygen
}
