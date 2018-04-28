extension ArraySlice: BytesRepresentable where Element == UInt8 {
    public var bytes: [UInt8] { return Array(self) }

    public init (bytes: [UInt8]) {
        self.init(bytes)
    }
}
