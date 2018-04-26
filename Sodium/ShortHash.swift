import Foundation
import Clibsodium

public class ShortHash {
    public let Bytes = Int(crypto_shorthash_bytes())

    /**
     Computes short but unpredictable (without knowing the secret key) values suitable for picking a list in a hash table for a given key.

     - Parameter message: The data to be hashed.
     - Parameter key: The hash key.  Must be of length `KeyBytes`. Can be created using `RandomBytes.buf()`.

     - Returns: The computed fingerprint.
     */
    public func hash(message: Data, key: Data) -> Data? {
        guard key.count == KeyBytes else { return nil }
        var output = Data(count: Bytes)

        guard .SUCCESS == output.withUnsafeMutableBytes({ outputPtr in
            message.withUnsafeBytes { messagePtr in
                key.withUnsafeBytes { keyPtr in
                    crypto_shorthash(outputPtr, messagePtr, CUnsignedLongLong(message.count), keyPtr).exitCode
                }
            }
        }) else { return nil }

        return output
    }
}

extension ShortHash: SecretKeyGenerator {
    public var KeyBytes: Int { return Int(crypto_shorthash_keybytes()) }
    public typealias Key = Data

    static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_shorthash_keygen
}
