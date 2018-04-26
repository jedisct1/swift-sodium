import Foundation

protocol KeyPairProtocol {
    associatedtype PublicKey where PublicKey == Data
    associatedtype SecretKey where SecretKey == Data
    var publicKey: PublicKey { get }
    var secretKey: SecretKey { get }

    init (publicKey: PublicKey, secretKey: SecretKey)
}
