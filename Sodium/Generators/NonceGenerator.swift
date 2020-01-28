import Foundation
#if SWIFT_PACKAGE
import Clibsodium
#else
import Sodium.Clibsodium
#endif

public protocol NonceGenerator {
    var NonceBytes: Int { get }
    associatedtype Nonce where Nonce == Bytes
}

extension NonceGenerator {
    /**
     Generates a random nonce.

     - Returns: A nonce.
     */
    public func nonce() -> Nonce {
        var nonce = Bytes(count: NonceBytes)
        randombytes_buf(&nonce, NonceBytes)
        return nonce
    }
}
