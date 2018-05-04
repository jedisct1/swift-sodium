#if swift(>=4.1)
extension Array: BytesRepresentable where Element == UInt8 {
    public var bytes: [UInt8] { return self }

    public init (bytes: [UInt8]) {
        self = bytes
    }
}
#endif
