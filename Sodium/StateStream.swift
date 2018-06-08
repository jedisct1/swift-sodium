protocol StateStream {
    associatedtype State

    static var capacity: Int { get }
}
