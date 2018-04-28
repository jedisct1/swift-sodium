import Foundation
import Clibsodium

public struct SecretBox {
    public let MacBytes = Int(crypto_secretbox_macbytes())
    public typealias MAC = Bytes
}

extension SecretBox {
    /**
     Encrypts a message with a shared secret key.

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The shared secret key.

     - Returns: A `Bytes` object containing the nonce and authenticated ciphertext.
     */
    public func seal(message: BytesRepresentable, secretKey: Key) -> Bytes? {
        guard let (authenticatedCipherText, nonce): (Bytes, Nonce) = seal(
            message: message,
            secretKey: secretKey
        ) else { return nil }
        return nonce + authenticatedCipherText
    }

    /**
     Encrypts a message with a shared secret key.

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The shared secret key.

     - Returns: The authenticated ciphertext and encryption nonce.
     */
    public func seal(message: BytesRepresentable, secretKey: Key) -> (authenticatedCipherText: Bytes, nonce: Nonce)? {
        let message = message.bytes
        guard secretKey.count == KeyBytes else { return nil }
        var authenticatedCipherText = Bytes(count: message.count + MacBytes)
        let nonce = self.nonce()

        guard .SUCCESS == crypto_secretbox_easy (
            &authenticatedCipherText,
            message, UInt64(message.count),
            nonce,
            secretKey
        ).exitCode else { return nil }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    /**
     Encrypts a message with a shared secret key (detached mode).

     - Parameter message: The message to encrypt.
     - Parameter secretKey: The shared secret key.

     - Returns: The encrypted ciphertext, encryption nonce, and authentication tag.
     */
    public func seal(message: BytesRepresentable, secretKey: Key) -> (cipherText: Bytes, nonce: Nonce, mac: MAC)? {
        guard secretKey.count == KeyBytes else { return nil }

        let message = message.bytes
        var cipherText = Bytes(count: message.count)
        var mac = Bytes(count: MacBytes)
        let nonce = self.nonce()

        guard .SUCCESS == crypto_secretbox_detached (
            &cipherText,
            &mac,
            message, UInt64(message.count),
            nonce,
            secretKey
        ).exitCode else { return nil }

        return (cipherText: cipherText, nonce: nonce, mac: mac)
    }
}

extension SecretBox {
    /**
     Decrypts a message with a shared secret key.

     - Parameter nonceAndAuthenticatedCipherText: A `Bytes` object containing the nonce and authenticated ciphertext.
     - Parameter secretKey: The shared secret key.

     - Returns: The decrypted message.
     */
    public func open(nonceAndAuthenticatedCipherText: BytesRepresentable, secretKey: Key) -> Bytes? {
        let nonceAndAuthenticatedCipherText = nonceAndAuthenticatedCipherText.bytes
        guard nonceAndAuthenticatedCipherText.count >= MacBytes + NonceBytes else { return nil }
        let nonce = nonceAndAuthenticatedCipherText[..<NonceBytes].bytes as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText[NonceBytes...].bytes

        return open(authenticatedCipherText: authenticatedCipherText, secretKey: secretKey, nonce: nonce)
    }

    /**
     Decrypts a message with a shared secret key and encryption nonce.

     - Parameter authenticatedCipherText: The authenticated ciphertext.
     - Parameter secretKey: The shared secret key.
     - Parameter nonce: The encryption nonce.

     - Returns: The decrypted message.
     */
    public func open(authenticatedCipherText: BytesRepresentable, secretKey: Key, nonce: Nonce) -> Bytes? {
        let authenticatedCipherText = authenticatedCipherText.bytes
        guard authenticatedCipherText.count >= MacBytes else { return nil }
        var message = Bytes(count: authenticatedCipherText.count - MacBytes)

        guard .SUCCESS == crypto_secretbox_open_easy (
            &message,
            authenticatedCipherText, UInt64(authenticatedCipherText.count),
            nonce,
            secretKey
        ).exitCode else { return nil }

        return message
    }

    /**
     Decrypts a message with a shared secret key, encryption nonce, and authentication tag.

     - Parameter cipherText: The encrypted ciphertext.
     - Parameter secretKey: The shared secret key.
     - Parameter nonce: The encryption nonce.

     - Returns: The decrypted message.
     */
    public func open(cipherText: BytesRepresentable, secretKey: Key, nonce: Nonce, mac: MAC) -> Bytes? {
        guard nonce.count == NonceBytes,
              mac.count == MacBytes,
              secretKey.count == KeyBytes
        else { return nil }

        let cipherText = cipherText.bytes
        var message = Bytes(count: cipherText.count)

        guard .SUCCESS == crypto_secretbox_open_detached (
            &message,
            cipherText,
            mac,
            UInt64(cipherText.count),
            nonce,
            secretKey
        ).exitCode else { return nil }

        return message
    }
}

extension SecretBox: NonceGenerator {
    public var NonceBytes: Int { return Int(crypto_secretbox_noncebytes()) }
    public typealias Nonce = Bytes
}

extension SecretBox: SecretKeyGenerator {
    public typealias Key = Bytes
    public var KeyBytes: Int { return Int(crypto_secretbox_keybytes()) }

    static let keygen: (_ k: UnsafeMutablePointer<UInt8>) -> Void = crypto_secretbox_keygen
}
