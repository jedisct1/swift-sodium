protocol StateStream {
    associatedtype State

    static var capacity: Int { get }
    var state: UnsafeMutablePointer<State> { get set }
}

extension StateStream {
    func free() {
        let rawState = UnsafeMutableRawPointer(state).bindMemory(
            to: UInt8.self,
            capacity: Self.capacity
        )

        #if swift(>=4.1)
        rawState.deallocate()
        #else
        rawState.deallocate(capacity: 1)
        #endif
    }

    static func gen(capacity bytes: Int) -> UnsafeMutablePointer<State> {
        let rawState = UnsafeMutablePointer<UInt8>.allocate(capacity: bytes)

        return UnsafeMutableRawPointer(rawState).bindMemory(
            to: State.self,
            capacity: 1
        )
    }
}
