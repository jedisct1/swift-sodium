import Foundation

public typealias Bytes = [UInt8]

extension [UInt8] {
    init(count bytes: Int) {
        self.init(repeating: 0, count: bytes)
    }

    public var utf8String: String? {
        String(data: Data(self), encoding: .utf8)
    }
}

extension ArraySlice where Element == UInt8 {
    var bytes: Bytes {
        Bytes(self)
    }
}

public extension String {
    var bytes: Bytes {
        Bytes(utf8)
    }
}
