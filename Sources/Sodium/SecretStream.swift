import Clibsodium
import Foundation

public struct SecretStream {
    public let xchacha20poly1305 = XChaCha20Poly1305()
}

public extension SecretStream {
    struct XChaCha20Poly1305 {
        public static let ABytes = Int(crypto_secretstream_xchacha20poly1305_abytes())
        public static let HeaderBytes = Int(crypto_secretstream_xchacha20poly1305_headerbytes())
        public static let KeyBytes = Int(crypto_secretstream_xchacha20poly1305_keybytes())
        public typealias Header = Bytes
    }
}

public extension SecretStream.XChaCha20Poly1305 {
    enum Tag: UInt8 {
        case MESSAGE = 0x00
        case PUSH = 0x01
        case REKEY = 0x02
        case FINAL = 0x03
    }
}

public extension SecretStream.XChaCha20Poly1305 {
    class PushStream {
        private var state: crypto_secretstream_xchacha20poly1305_state
        private var _header: Header

        init?(secretKey: Key) {
            guard secretKey.count == KeyBytes else { return nil }

            state = crypto_secretstream_xchacha20poly1305_state()

            _header = Bytes(count: HeaderBytes)
            guard crypto_secretstream_xchacha20poly1305_init_push(
                &state,
                &_header,
                secretKey
            ).exitCode == .SUCCESS else { return nil }
        }
    }
}

public extension SecretStream.XChaCha20Poly1305 {
    class PullStream {
        private var state: crypto_secretstream_xchacha20poly1305_state

        init?(secretKey: Key, header: Header) {
            guard header.count == HeaderBytes, secretKey.count == KeyBytes else {
                return nil
            }

            state = crypto_secretstream_xchacha20poly1305_state()

            guard crypto_secretstream_xchacha20poly1305_init_pull(
                &state,
                header,
                secretKey
            ).exitCode == .SUCCESS else { return nil }
        }
    }
}

public extension SecretStream.XChaCha20Poly1305 {
    /**
     Creates a new stream using the secret key `secretKey`

     - Parameter secretKey: The secret key.

     - Returns: A `PushStreamObject`. The stream header can be obtained by
     calling the `header()` method of that returned object.
     */
    func initPush(secretKey: Key) -> PushStream? {
        PushStream(secretKey: secretKey)
    }

    /**
     Starts reading a stream, whose header is `header`.

     - Parameter secretKey: The secret key.
     - Parameter header: The header.

     - Returns: The stream to decrypt messages from.
     */
    func initPull(secretKey: Key, header: Header) -> PullStream? {
        PullStream(secretKey: secretKey, header: header)
    }
}

public extension SecretStream.XChaCha20Poly1305.PushStream {
    typealias Header = SecretStream.XChaCha20Poly1305.Header

    /**
     The header of the stream, required to decrypt it.

     - Returns: The stream header.
     */
    func header() -> Header {
        _header
    }
}

public extension SecretStream.XChaCha20Poly1305.PushStream {
    typealias Tag = SecretStream.XChaCha20Poly1305.Tag
    internal typealias XChaCha20Poly1305 = SecretStream.XChaCha20Poly1305

    /**
     Encrypts and authenticate a new message. Optionally also authenticate `ad`.

     - Parameter message: The message to encrypt.
     - Parameter tag: The tag to attach to the message. By default `.MESSAGE`.
     You may want to use `.FINAL` for the last message of the stream instead.
     - Parameter ad: Optional additional data to authenticate.

     - Returns: The ciphertext.
     */
    func push(message: Bytes, tag: Tag = .MESSAGE, ad: Bytes? = nil) -> Bytes? {
        let _ad = ad ?? Bytes(count: 0)
        var cipherText = Bytes(count: message.count + XChaCha20Poly1305.ABytes)
        guard crypto_secretstream_xchacha20poly1305_push(
            &state,
            &cipherText,
            nil,
            message, UInt64(message.count),
            _ad, UInt64(_ad.count),
            tag.rawValue
        ).exitCode == .SUCCESS else { return nil }

        return cipherText
    }

    /**
     Performs an explicit key rotation.
     */
    func rekey() {
        crypto_secretstream_xchacha20poly1305_rekey(&state)
    }
}

public extension SecretStream.XChaCha20Poly1305.PullStream {
    typealias Tag = SecretStream.XChaCha20Poly1305.Tag
    internal typealias XChaCha20Poly1305 = SecretStream.XChaCha20Poly1305

    /**
     Decrypts a new message off the stream.

     - Parameter cipherText: The encrypted message.
     - Parameter ad: Optional additional data to authenticate.

     - Returns: The decrypted message, as well as the tag attached to it.
     */
    func pull(cipherText: Bytes, ad: Bytes? = nil) -> (Bytes, Tag)? {
        guard cipherText.count >= XChaCha20Poly1305.ABytes else { return nil }
        var message = Bytes(count: cipherText.count - XChaCha20Poly1305.ABytes)
        let _ad = ad ?? Bytes(count: 0)
        var _tag: UInt8 = 0
        let result = crypto_secretstream_xchacha20poly1305_pull(
            &state,
            &message,
            nil,
            &_tag,
            cipherText, UInt64(cipherText.count),
            _ad, UInt64(_ad.count)
        ).exitCode

        guard result == .SUCCESS, let tag = Tag(rawValue: _tag) else {
            return nil
        }
        return (message, tag)
    }

    /**
     Performs an explicit key rotation.
     */
    func rekey() {
        crypto_secretstream_xchacha20poly1305_rekey(&state)
    }
}

extension SecretStream.XChaCha20Poly1305: SecretKeyGenerator {
    public var KeyBytes: Int {
        SecretStream.XChaCha20Poly1305.KeyBytes
    }

    public typealias Key = Bytes

    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_secretstream_xchacha20poly1305_keygen
}
