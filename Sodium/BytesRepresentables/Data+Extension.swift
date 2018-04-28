import Foundation

extension Data: BytesRepresentable {
    public var bytes: [UInt8] { return Array(self) }
}
