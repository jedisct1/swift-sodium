import Foundation
import Clibsodium

public struct SHA512Hash: Sendable {
    public let Bytes = Int(crypto_hash_sha512_bytes())
}

extension SHA512Hash {
    /**
     Computes the SHA-512 hash of the given data.

     - Parameter message: The data to be hashed.

     - Returns: The computed SHA-512 hash.
     */
    public func hash(message: Bytes) -> Bytes? {
        var output = Array<UInt8>(count: Bytes)

        guard .SUCCESS == crypto_hash_sha512 (
            &output,
            message, UInt64(message.count)
        ).exitCode else { return nil }
        return output
    }
}
