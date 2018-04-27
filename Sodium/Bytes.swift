import Foundation

public typealias Bytes = Array<UInt8>

extension Array where Element == UInt8 {
    init (count bytes: Int) {
        self.init(repeating: 0, count: bytes)
    }
}

extension ArraySlice where Element == UInt8 {
    var bytes: Bytes { return Bytes(self) }
}

public extension String {
    var bytes: Bytes { return Bytes(self.utf8) }
}
