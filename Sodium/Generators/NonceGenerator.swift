import Foundation
import Clibsodium

protocol NonceGenerator {
    var NonceBytes: Int { get }
    associatedtype Nonce where Nonce == BytesContainer
}

extension NonceGenerator {
    /**
     Generates a random nonce.

     - Returns: A nonce.
     */
    public func nonce() -> Nonce {
        var nonce = BytesContainer(count: NonceBytes)
        randombytes_buf(&nonce.bytes, NonceBytes)
        return nonce
    }
}
