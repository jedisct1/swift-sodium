protocol StateStream {
    associatedtype State

    var capacity: Int { get }
    var state: UnsafeMutablePointer<State> { get set }
}

extension StateStream {
    var rawState: UnsafeMutablePointer<UInt8> {
        return UnsafeMutableRawPointer(state).bindMemory(
            to: UInt8.self,
            capacity: capacity
        )
    }

    func free() {
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
