import Foundation
import Clibsodium

public struct SHA256Hash: Sendable {
    public let Bytes = Int(crypto_hash_sha256_bytes())
}

extension SHA256Hash {
    /**
     Computes short but unpredictable (without knowing the secret key) values suitable for picking a list in a hash table for a given key.

     - Parameter message: The data to be hashed.

     - Returns: The computed SHA256 hash.
     */
    public func hash(message: Bytes) -> Bytes? {
        var output = Array<UInt8>(count: Bytes)

        guard .SUCCESS == crypto_hash_sha256 (
            &output,
            message, UInt64(message.count)
        ).exitCode else { return nil }
        return output
    }
}
