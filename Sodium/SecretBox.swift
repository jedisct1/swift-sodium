import Foundation
import Clibsodium

public struct SecretBox {
    public let MacBytes = Int(crypto_secretbox_macbytes())
    public typealias MAC = Bytes
}

extension SecretBox {
    /// Encrypts a message with a shared secret key
    ///
    /// This method generates a random nonce and prepends it to the encrypted ciphertext.
    /// The result can be directly passed to `open(nonceAndAuthenticatedCipherText:secretKey:)`
    /// for decryption.
    ///
    /// - Parameters:
    ///   - message: The plaintext message to encrypt
    ///   - secretKey: The 32-byte shared secret key
    /// - Returns: Combined nonce (24 bytes) + authenticated ciphertext, or nil on failure
    ///
    /// - Example:
    /// ```swift
    /// let sodium = Sodium()
    /// let message = "Secret message".bytes
    /// let key = sodium.secretBox.key()
    ///
    /// if let encrypted = sodium.secretBox.seal(message: message, secretKey: key) {
    ///     // encrypted contains nonce + ciphertext
    ///     print("Encrypted: \(encrypted.count) bytes")
    /// }
    /// ```
    public func seal(message: Bytes, secretKey: Key) -> Bytes? {
        guard let (authenticatedCipherText, nonce): (Bytes, Nonce) = seal(
            message: message,
            secretKey: secretKey
        ) else { return nil }
        return nonce + authenticatedCipherText
    }

    /// Encrypts a message with a shared secret key (separated nonce)
    ///
    /// This method generates a random nonce and returns it separately from the ciphertext.
    /// This is useful when you need to store or transmit the nonce separately.
    ///
    /// - Parameters:
    ///   - message: The plaintext message to encrypt
    ///   - secretKey: The 32-byte shared secret key
    /// - Returns: Tuple containing authenticated ciphertext and nonce, or nil on failure
    ///
    /// - Example:
    /// ```swift
    /// let sodium = Sodium()
    /// let message = "Secret message".bytes
    /// let key = sodium.secretBox.key()
    ///
    /// if let (ciphertext, nonce) = sodium.secretBox.seal(message: message, secretKey: key) {
    ///     print("Ciphertext: \(ciphertext.count) bytes")
    ///     print("Nonce: \(nonce.count) bytes")
    /// }
    /// ```
    public func seal(message: Bytes, secretKey: Key) -> (authenticatedCipherText: Bytes, nonce: Nonce)? {
        let nonce = self.nonce()

        guard let authenticatedCipherText = seal(message: message, secretKey: secretKey, nonce: nonce) else {
            return nil
        }

        return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
    }

    /// Encrypts a message with a shared secret key and specific nonce
    ///
    /// - Warning: Never reuse a nonce with the same key! Doing so compromises security.
    /// Consider using the methods that generate random nonces automatically.
    ///
    /// - Parameters:
    ///   - message: The plaintext message to encrypt
    ///   - secretKey: The 32-byte shared secret key
    ///   - nonce: The 24-byte nonce (must be unique for this key)
    /// - Returns: Authenticated ciphertext (message.count + 16 bytes), or nil on failure
    ///
    /// - Example:
    /// ```swift
    /// let sodium = Sodium()
    /// let message = "Secret message".bytes
    /// let key = sodium.secretBox.key()
    /// let nonce = sodium.secretBox.nonce() // Generate once, never reuse!
    ///
    /// if let encrypted = sodium.secretBox.seal(
    ///     message: message,
    ///     secretKey: key,
    ///     nonce: nonce
    /// ) {
    ///     print("Encrypted: \(encrypted.count) bytes")
    /// }
    /// ```
    public func seal(message: Bytes, secretKey: Key, nonce: Nonce) -> Bytes? {
        guard secretKey.count == KeyBytes else { return nil }
        var authenticatedCipherText = Bytes(count: message.count + MacBytes)

        guard .SUCCESS == crypto_secretbox_easy (
            &authenticatedCipherText,
            message, UInt64(message.count),
            nonce,
            secretKey
        ).exitCode else { return nil }

        return authenticatedCipherText
    }

    /// Encrypts a message with a shared secret key (detached mode)
    ///
    /// In detached mode, the authentication tag is returned separately from the ciphertext.
    /// This is useful for protocols that need to handle the MAC separately.
    ///
    /// - Parameters:
    ///   - message: The plaintext message to encrypt
    ///   - secretKey: The 32-byte shared secret key
    /// - Returns: Tuple containing ciphertext, nonce, and MAC, or nil on failure
    ///
    /// - Example:
    /// ```swift
    /// let sodium = Sodium()
    /// let message = "Secret message".bytes
    /// let key = sodium.secretBox.key()
    ///
    /// if let (ciphertext, nonce, mac) = sodium.secretBox.seal(
    ///     message: message,
    ///     secretKey: key
    /// ) {
    ///     print("Ciphertext: \(ciphertext.count) bytes")
    ///     print("MAC: \(mac.count) bytes")
    ///     // Store or transmit ciphertext, nonce, and mac separately
    /// }
    /// ```
    public func seal(message: Bytes, secretKey: Key) -> (cipherText: Bytes, nonce: Nonce, mac: MAC)? {
        guard secretKey.count == KeyBytes else { return nil }

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
    public func open(nonceAndAuthenticatedCipherText: Bytes, secretKey: Key) -> Bytes? {
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
    public func open(authenticatedCipherText: Bytes, secretKey: Key, nonce: Nonce) -> Bytes? {
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
    public func open(cipherText: Bytes, secretKey: Key, nonce: Nonce, mac: MAC) -> Bytes? {
        guard nonce.count == NonceBytes,
              mac.count == MacBytes,
              secretKey.count == KeyBytes
        else { return nil }

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

    public static let keygen: (_ k: UnsafeMutablePointer<UInt8>) -> Void = crypto_secretbox_keygen
}
