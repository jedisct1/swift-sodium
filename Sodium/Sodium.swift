import Clibsodium
import Foundation

public struct Sodium {
    public enum InitError: Error {
        case code(Int32)
    }

    public let box = Box()
    public let secretBox = SecretBox()
    public let genericHash = GenericHash()
    public let pwHash = PWHash()
    public let randomBytes = RandomBytes()
    public let shortHash = ShortHash()
    public let sign = Sign()
    public let utils = Utils()
    public let keyExchange = KeyExchange()
    public let auth = Auth()
    public let stream = Stream()
    public let keyDerivation = KeyDerivation()
    public let secretStream = SecretStream()
    public let aead = Aead()

    public init() throws {
        let code = Sodium.initCode
        guard code >= 0 else {
            throw InitError.code(code)
        }
    }
}

extension Sodium {
    private static let initCode: Int32 = {
        return sodium_init()
    }()
}
