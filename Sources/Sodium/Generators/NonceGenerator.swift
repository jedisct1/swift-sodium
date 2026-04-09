import Clibsodium
import Foundation

public protocol NonceGenerator {
    var NonceBytes: Int { get }
    associatedtype Nonce where Nonce == Bytes
}

public extension NonceGenerator {
    /**
     Generates a random nonce.

     - Returns: A nonce.
     */
    func nonce() -> Nonce {
        var nonce = Bytes(count: NonceBytes)
        randombytes_buf(&nonce, NonceBytes)
        return nonce
    }
}
