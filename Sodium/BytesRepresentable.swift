public protocol BytesRepresentable {
    var bytes: [UInt8] { get }
    init? (bytes: [UInt8])
}

public extension BytesRepresentable {
    init? (bytes: BytesRepresentable) {
        self.init(bytes: bytes.bytes)
    }
}
