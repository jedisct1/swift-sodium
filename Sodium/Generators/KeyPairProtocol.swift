import Foundation

protocol KeyPairProtocol {
    associatedtype PublicKey where PublicKey == BytesContainer
    associatedtype SecretKey where SecretKey == BytesContainer
    var publicKey: PublicKey { get }
    var secretKey: SecretKey { get }

    init (publicKey: PublicKey, secretKey: SecretKey)
}
