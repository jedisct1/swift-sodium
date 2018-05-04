import Foundation

public struct BytesContainer {
    public var bytes: [UInt8]

    public init <C: Collection>(bytes: C) where C.Element == UInt8 {
        self.bytes = Array(bytes)
    }

    public init (_ bytesRepresentation: BytesRepresentable) {
        bytes = bytesRepresentation.bytes
    }

    public init (count bytes: Int) {
        self.bytes = Array(repeating: 0, count: bytes)
    }

    public init () {
        bytes = []
    }
}

extension BytesContainer: BytesRepresentable {}

public extension BytesContainer {
    static func + (lhs: BytesContainer, rhs: BytesContainer) -> BytesContainer {
        return self.init(bytes: lhs.bytes + rhs.bytes)
    }

    subscript <R>(r: R) -> BytesContainer where R: RangeExpression, Index == R.Bound {
        return BytesContainer(bytes: bytes[r])
    }

}

extension BytesContainer: MutableCollection {
    public typealias Index = Array<UInt8>.Index
    public typealias Element = Array<UInt8>.Element

    public var startIndex: Index { return bytes.startIndex }
    public var endIndex: Index { return bytes.endIndex }
    public var count: Int { return bytes.count }

    public func index(after i: Index) -> Index {
        return bytes.index(after: i)
    }

    public subscript(position: Index) -> UInt8 {
        get { return bytes[position] }
        set (newValue) { bytes[position] = newValue }
    }
}

extension BytesContainer: Equatable {
    public static func == (lhs: BytesContainer, rhs: BytesContainer) -> Bool {
        return lhs.bytes == rhs.bytes
    }
}

extension BytesContainer: ExpressibleByArrayLiteral {
    public typealias ArrayLiteralElement = Element

    public init(arrayLiteral elements: Element...) {
        bytes = elements
    }
}
