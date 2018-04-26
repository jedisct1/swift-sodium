import Foundation
import Clibsodium

public class SecretStream {
    public let xchacha20poly1305 = XChaCha20Poly1305()

    public class XChaCha20Poly1305 {
        public static let ABytes = Int(crypto_secretstream_xchacha20poly1305_abytes())
        public static let HeaderBytes = Int(crypto_secretstream_xchacha20poly1305_headerbytes())
        public static let KeyBytes = Int(crypto_secretstream_xchacha20poly1305_keybytes())
        public enum Tag: UInt8 {
            case MESSAGE = 0x00
            case PUSH = 0x01
            case REKEY = 0x02
            case FINAL = 0x03
        }
        public typealias Key = Data
        public typealias Header = Data

        /**
         Generates a secret key.

         - Returns: The generated key.
         */
        public func key() -> Key {
            var secretKey = Data(count: XChaCha20Poly1305.KeyBytes)
            secretKey.withUnsafeMutableBytes { secretKeyPtr in
                crypto_secretstream_xchacha20poly1305_keygen(secretKeyPtr)
            }
            return secretKey
        }

        /**
         Creates a new stream using the secret key `secretKey`

         - Parameter secretKey: The secret key.

         - Returns: A `PushStreamObject`. The stream header can be obtained by
         calling the `header()` method of that returned object.
         */
        public func initPush(secretKey: Key) -> PushStream? {
            return PushStream(secretKey: secretKey)
        }

        /**
         Starts reading a stream, whose header is `header`.

         - Parameter secretKey: The secret key.
         - Parameter header: The header.

         - Returns: The stream to decrypt messages from.
         */
        public func initPull(secretKey: Key, header: Header) -> PullStream? {
            return PullStream(secretKey: secretKey, header: header)
        }

        public class PushStream: StateStream {
            typealias State = crypto_secretstream_xchacha20poly1305_state

            static let capacity = crypto_secretstream_xchacha20poly1305_statebytes()
            private var state: UnsafeMutablePointer<State>

            private var _header: Header

            init?(secretKey: Key) {
                guard secretKey.count == KeyBytes else { return nil }

                state = PushStream.generate()
                _header = Data(count: HeaderBytes)
                guard .SUCCESS == secretKey.withUnsafeBytes({ secretKeyPtr in
                    _header.withUnsafeMutableBytes { headerPtr in
                        crypto_secretstream_xchacha20poly1305_init_push(state, headerPtr, secretKeyPtr).exitCode
                    }
                }) else {
                    free()
                    return nil
                }
            }

            /**
             The header of the stream, required to decrypt it.

             - Returns: The stream header.
             */
            public func header() -> Header {
                return _header
            }

            /**
             Encrypts and authenticate a new message. Optionally also authenticate `ad`.

             - Parameter message: The message to encrypt.
             - Parameter tag: The tag to attach to the message. By default `.MESSAGE`.
             You may want to use `.FINAL` for the last message of the stream instead.
             - Parameter ad: Optional additional data to authenticate.

             - Returns: The ciphertext.
             */
            public func push(message: Data, tag: Tag = .MESSAGE, ad: Data? = nil) -> Data? {
                let _ad = ad ?? Data(count: 0)
                var cipherText = Data(count: message.count + ABytes)
                guard .SUCCESS == cipherText.withUnsafeMutableBytes({ cipherTextPtr in
                    _ad.withUnsafeBytes { adPtr in
                        message.withUnsafeBytes { messagePtr in
                            crypto_secretstream_xchacha20poly1305_push(state, cipherTextPtr, nil, messagePtr, CUnsignedLongLong(message.count), adPtr, CUnsignedLongLong(_ad.count), tag.rawValue).exitCode
                        }
                    }
                }) else { return nil }

                return cipherText
            }

            /**
             Performs an explicit key rotation.
             */
            public func rekey() {
                crypto_secretstream_xchacha20poly1305_rekey(state)
            }

            private func free() {
                PushStream.free(state)
            }

            deinit {
                free()
            }
        }

        public class PullStream: StateStream {
            typealias State = crypto_secretstream_xchacha20poly1305_state

            static let capacity = crypto_secretstream_xchacha20poly1305_statebytes()
            private var state: UnsafeMutablePointer<State>

            init?(secretKey: Key, header: Header) {
                guard header.count == HeaderBytes, secretKey.count == KeyBytes else {
                    return nil
                }
                state = PushStream.generate()
                guard .SUCCESS == secretKey.withUnsafeBytes({ secretKeyPtr in
                    header.withUnsafeBytes { headerPtr in
                        crypto_secretstream_xchacha20poly1305_init_pull(state, headerPtr, secretKeyPtr).exitCode
                    }
                }) else {
                    free()
                    return nil
                }
            }

            /**
             Decrypts a new message off the stream.

             - Parameter cipherText: The encrypted message.
             - Parameter ad: Optional additional data to authenticate.

             - Returns: The decrypted message, as well as the tag attached to it.
             */
            public func pull(cipherText: Data, ad: Data? = nil) -> (Data, Tag)? {
                guard cipherText.count >= ABytes else { return nil }
                var message = Data(count: cipherText.count - ABytes)
                let _ad = ad ?? Data(count: 0)
                var _tag: UInt8 = 0
                let result = cipherText.withUnsafeBytes { cipherTextPtr in
                    _ad.withUnsafeBytes { adPtr in
                        message.withUnsafeMutableBytes { messagePtr in
                            crypto_secretstream_xchacha20poly1305_pull(state, messagePtr, nil, &_tag, cipherTextPtr, CUnsignedLongLong(cipherText.count), adPtr, CUnsignedLongLong(_ad.count)).exitCode
                        }
                    }
                }
                guard result == .SUCCESS, let tag = Tag(rawValue: _tag) else {
                    return nil
                }
                return (message, tag)
            }

            /**
             Performs an explicit key rotation.
             */
            public func rekey() {
                crypto_secretstream_xchacha20poly1305_rekey(state)
            }

            private func free() {
                PullStream.free(state)
            }

            deinit {
                free()
            }
        }
    }
}
