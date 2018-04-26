import Foundation

protocol SecretKeyGenerator {
    var KeyBytes: Int { get }
    associatedtype Key where Key == Data

    static var keygen: (_ k: UnsafeMutablePointer<UInt8>) -> Void { get }
}

extension SecretKeyGenerator {
    /**
     Generates a secret key.

     - Returns: The generated key.
     */
    public func key() -> Key {
        var k = Data(count: KeyBytes)
        k.withUnsafeMutableBytes { kPtr in Self.keygen(kPtr) }
        return k
    }
}
