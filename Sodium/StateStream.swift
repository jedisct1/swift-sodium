protocol StateStream {
    associatedtype State

    static var capacity: Int { get }
}

extension StateStream {
    static func free(_ state: UnsafeMutablePointer<State>) {
        let rawState = UnsafeMutableRawPointer(state).bindMemory(
            to: UInt8.self,
            capacity: capacity
        )

        #if swift(>=4.1)
        rawState.deallocate()
        #else
        rawState.deallocate(capacity: 1)
        #endif
    }

    static func generate() -> UnsafeMutablePointer<State> {
        let rawState = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)

        return UnsafeMutableRawPointer(rawState).bindMemory(
            to: State.self,
            capacity: 1
        )
    }
}
