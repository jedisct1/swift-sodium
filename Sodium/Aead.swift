import Foundation
import Clibsodium

public struct Aead {
    public let xchacha20poly1305ietf = XChaCha20Poly1305Ietf()
}

extension Aead {
    public struct XChaCha20Poly1305Ietf {
        public let ABytes = Int(crypto_aead_xchacha20poly1305_ietf_abytes())
        public typealias MAC = BytesContainer
    }
}

extension Aead.XChaCha20Poly1305Ietf {
    /**
     Encrypts a message with a shared secret key.

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The shared secret key.
     - Parameter additionalData: A typical use for these data is to authenticate version numbers, timestamps or monotonically increasing counters

     - Returns: A `Bytes` object containing the nonce and authenticated ciphertext.
     */
    public func encrypt(message: BytesRepresentable, secretKey: Key, additionalData: BytesRepresentable? = nil) -> BytesContainer? {
        guard let (authenticatedCipherText, nonce): (BytesContainer, Nonce) = encrypt(
            message: message,
            secretKey: secretKey,
            additionalData: additionalData
        ) else { return nil }

        return nonce + authenticatedCipherText
    }

    /**
     Encrypts a message with a shared secret key.

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The shared secret key.
     - Parameter additionalData: A typical use for these data is to authenticate version numbers, timestamps or monotonically increasing counters

     - Returns: The authenticated ciphertext and encryption nonce.
     */
    public func encrypt(message: BytesRepresentable, secretKey: Key, additionalData: BytesRepresentable? = nil) -> (authenticatedCipherText: BytesContainer, nonce: Nonce)? {
        guard secretKey.count == KeyBytes else { return nil }

        let (message, additionalData) = (message.bytes, additionalData?.bytes)
        var authenticatedCipherText = BytesContainer(count: message.count + ABytes)
        var authenticatedCipherTextLen: UInt64 = 0
        let nonce = self.nonce()

        guard .SUCCESS == crypto_aead_xchacha20poly1305_ietf_encrypt (
            &authenticatedCipherText.bytes, &authenticatedCipherTextLen,
            message, UInt64(message.count),
            additionalData, UInt64(additionalData?.count ?? 0),
            nil, nonce.bytes, secretKey.bytes
        ).exitCode else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }
}

extension Aead.XChaCha20Poly1305Ietf {
    /**
     Decrypts a message with a shared secret key.
     
     - Parameter nonceAndAuthenticatedCipherText: A `Bytes` object containing the nonce and authenticated ciphertext.
     - Parameter secretKey: The shared secret key.
     - Parameter additionalData: Must be used same `Bytes` that was used to encrypt, if `Bytes` deferred will return nil
     
     - Returns: The decrypted message.
     */
    public func decrypt(nonceAndAuthenticatedCipherText: BytesRepresentable, secretKey: Key, additionalData: BytesRepresentable? = nil) -> BytesContainer? {
        let nonceAndAuthenticatedCipherText = BytesContainer(nonceAndAuthenticatedCipherText)
        let additionalData = additionalData.flatMap(BytesContainer.init)
        guard nonceAndAuthenticatedCipherText.count >= ABytes + NonceBytes else { return nil }

        let nonce = nonceAndAuthenticatedCipherText[..<NonceBytes] as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText[NonceBytes...]

        return decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: secretKey, nonce: nonce, additionalData: additionalData)
    }
    
    /**
     Decrypts a message with a shared secret key.
     
     - Parameter authenticatedCipherText: A `Bytes` object containing authenticated ciphertext.
     - Parameter secretKey: The shared secret key.
     - Parameter additionalData: Must be used same `Bytes` that was used to encrypt, if `Bytes` deferred will return nil
     
     - Returns: The decrypted message.
     */
    public func decrypt(authenticatedCipherText: BytesRepresentable, secretKey: Key, nonce: Nonce, additionalData: BytesRepresentable? = nil) -> BytesContainer? {
        let authenticatedCipherText = authenticatedCipherText.bytes
        let additionalData = additionalData?.bytes
        guard authenticatedCipherText.count >= ABytes else { return nil }
        
        var message = BytesContainer(count: authenticatedCipherText.count - ABytes)
        var messageLen: UInt64 = 0

        guard .SUCCESS == crypto_aead_xchacha20poly1305_ietf_decrypt (
            &message.bytes, &messageLen,
            nil,
            authenticatedCipherText, UInt64(authenticatedCipherText.count),
            additionalData, UInt64(additionalData?.count ?? 0),
            nonce.bytes, secretKey.bytes
        ).exitCode else { return nil }

        return message
    }
}

extension Aead.XChaCha20Poly1305Ietf: NonceGenerator {
    public typealias Nonce = BytesContainer
    public var NonceBytes: Int { return Int(crypto_aead_xchacha20poly1305_ietf_npubbytes()) }
}

extension Aead.XChaCha20Poly1305Ietf: SecretKeyGenerator {
    public var KeyBytes: Int { return Int(crypto_aead_xchacha20poly1305_ietf_keybytes()) }
    public typealias Key = BytesContainer

    static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_aead_xchacha20poly1305_ietf_keygen
}
