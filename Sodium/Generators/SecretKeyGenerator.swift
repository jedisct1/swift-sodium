import Foundation

protocol SecretKeyGenerator {
    var KeyBytes: Int { get }
    associatedtype Key where Key == BytesContainer

    static var keygen: (_ k: UnsafeMutablePointer<UInt8>) -> Void { get }
}

extension SecretKeyGenerator {
    /**
     Generates a secret key.

     - Returns: The generated key.
     */
    public func key() -> Key {
        var k = BytesContainer(count: KeyBytes)
        Self.keygen(&k.bytes)
        return k
    }
}
