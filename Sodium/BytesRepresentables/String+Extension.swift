import Foundation

extension String: BytesRepresentable {
    public var bytes: [UInt8] { return Array(self.utf8) }

    public init? (bytes: [UInt8]) {
        self.init(data: Data(bytes: bytes), encoding: .utf8)
    }
}
