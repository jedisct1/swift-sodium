import Foundation
import Clibsodium

protocol NonceGenerator {
    var NonceBytes: Int { get }
    associatedtype Nonce where Nonce == Data
}

extension NonceGenerator {
    /**
     Generates a random nonce.

     - Returns: A nonce.
     */
    public func nonce() -> Nonce {
        var nonce = Data(count: NonceBytes)
        nonce.withUnsafeMutableBytes {
            noncePtr in randombytes_buf(noncePtr, NonceBytes)
        }
        return nonce
    }
}
