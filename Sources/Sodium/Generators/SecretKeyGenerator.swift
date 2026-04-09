import Foundation

public protocol SecretKeyGenerator {
    var KeyBytes: Int { get }
    associatedtype Key where Key == Bytes

    static var keygen: (_ k: UnsafeMutablePointer<UInt8>) -> Void { get }
}

public extension SecretKeyGenerator {
    /**
     Generates a secret key.

     - Returns: The generated key.
     */
    func key() -> Key {
        var k = Bytes(count: KeyBytes)
        Self.keygen(&k)
        return k
    }
}
