import Foundation
import Clibsodium

public struct HMAC {
    public static let HMACSHA256Bytes = Int(crypto_auth_hmacsha256_bytes())
    public static let HMACSHA512Bytes = Int(crypto_auth_hmacsha512_bytes())
    public static let HMACSHA512256Bytes = Int(crypto_auth_hmacsha512256_bytes())

    public let HMACSHA256KeyBytes = Int(crypto_auth_hmacsha256_keybytes())
    public let HMACSHA512KeyBytes = Int(crypto_auth_hmacsha512_keybytes())
    public let HMACSHA512256KeyBytes = Int(crypto_auth_hmacsha512256_keybytes())
}

extension HMAC {
    public enum Alg {
        case sha256
        case sha512
        case sha512256
    }

    /**
     This helper function creates a random key.

     - Parameter alg: the hashing algorithm (SHA-256, SHA-512 or SHA-512-256)

     - Returns: a random key or `nil` if the key cannot be created.
     */
    public func key(alg: Alg) -> Bytes? {
        var output: Bytes

        switch alg {
        case .sha256:
            output = Bytes(count: HMACSHA256KeyBytes)
            crypto_auth_hmacsha256_keygen(&output)
        case .sha512:
            output = Bytes(count: HMACSHA512KeyBytes)
            crypto_auth_hmacsha512_keygen(&output)
        case .sha512256:
            output = Bytes(count: HMACSHA512256KeyBytes)
            crypto_auth_hmacsha512256_keygen(&output)
        }

        return output
    }

    /**
     This function calculates a message authentication code (HMAC) for a single given message and a given key using the provided hash algorithm.

     - Parameter message: the message that should be authenticated
     - Parameter key: the key that is being used calculating the HMAC
     - Parameter alg: the hashing algorithm (SHA-256, SHA-512 or SHA-512-256)

     - Returns: an authenticator (HMAC) for the given message and key using the provided hash algorithm. If the HMAC cannot be calculated this method returns `nil`.
     */
    public func authenticate(message: Bytes, key: Bytes, alg: Alg) -> Bytes? {
        guard key.count == keyLength(alg: alg) else { return nil }

        var output: Bytes

        switch alg {
        case .sha256:
            output = Bytes(count: HMAC.HMACSHA256Bytes)
            guard .SUCCESS == crypto_auth_hmacsha256(&output, message, UInt64(message.count), key).exitCode else { return nil }
        case .sha512:
            output = Bytes(count: HMAC.HMACSHA512Bytes)
            guard .SUCCESS == crypto_auth_hmacsha512(&output, message, UInt64(message.count), key).exitCode else { return nil }
        case .sha512256:
            output = Bytes(count: HMAC.HMACSHA512256Bytes)
            guard .SUCCESS == crypto_auth_hmacsha512256(&output, message, UInt64(message.count), key).exitCode else { return nil }
        }

        return output
    }

    /**
     This function verifies that a given authenticator (HMAC) is correct for the given message and a key.

     - Parameter hmac: the authenticator (HMAC)
     - Parameter message: the message that is authenticated
     - Parameter key: the key that is being used verify the HMAC
     - Parameter alg: the hashing algorithm (SHA-256, SHA-512 or SHA-512-256) used for calculating the HMAC

     - Returns: true if the verification succeeds, false otherwise.
     */
    public func verify(hmac: Bytes, message: Bytes, key: Bytes, alg: Alg) -> Bool {
        guard key.count == keyLength(alg: alg) else { return false }

        switch alg {
        case .sha256:
            return .SUCCESS == crypto_auth_hmacsha256_verify(hmac, message, UInt64(message.count), key).exitCode
        case .sha512:
            return .SUCCESS == crypto_auth_hmacsha512_verify(hmac, message, UInt64(message.count), key).exitCode
        case .sha512256:
            return .SUCCESS == crypto_auth_hmacsha512256_verify(hmac, message, UInt64(message.count), key).exitCode
        }
    }

    private func keyLength(alg: Alg) -> Int {
        switch alg {
        case .sha256:
            return HMACSHA256KeyBytes
        case .sha512:
            return HMACSHA512KeyBytes
        case .sha512256:
            return HMACSHA512256KeyBytes
        }
    }
}

public protocol MultiPartHMAC {
    func update(message: Bytes) -> Bool
    func final() -> Bytes?
}

extension HMAC {
    public class MultiPartHMACSHA256: MultiPartHMAC {
        private var state: crypto_auth_hmacsha256_state

        init?(key: Bytes) {
            state = crypto_auth_hmacsha256_state()
            guard .SUCCESS == crypto_auth_hmacsha256_init(&state, key, key.count).exitCode else { return nil}
        }

        /**
         This function updates the HMAC by including another part of the message to be authenticated.

         - Parameter message: the message part

         - Returns: true if the given message part was included into the HMAC successfully, false otherwise.
         */
        public func update(message: Bytes) -> Bool {
            guard .SUCCESS == crypto_auth_hmacsha256_update(&state, message, UInt64(message.count)).exitCode else { return false }
            return true
        }

        /**
         This function returns the HMAC for the message that consists of all parts passed into the `update` method. After calling this method you should not call `update` again.

         - Returns: an authenticator (HMAC) for the given multi-part message or `nil` if the HMAC cannot be calculated.
         */
        public func final() -> Bytes? {
            var output = Bytes(count: HMAC.HMACSHA256Bytes)
            guard .SUCCESS == crypto_auth_hmacsha256_final(&state, &output).exitCode else { return nil }
            return output
        }
    }

    public class MultiPartHMACSHA512: MultiPartHMAC {
        private var state: crypto_auth_hmacsha512_state

        init?(key: Bytes) {
            state = crypto_auth_hmacsha512_state()
            guard .SUCCESS == crypto_auth_hmacsha512_init(&state, key, key.count).exitCode else { return nil}
        }

        /**
         This function updates the HMAC by including another part of the message to be authenticated.

         - Parameter message: the message part

         - Returns: true if the given message part was included into the HMAC successfully, false otherwise.
         */
        public func update(message: Bytes) -> Bool {
            guard .SUCCESS == crypto_auth_hmacsha512_update(&state, message, UInt64(message.count)).exitCode else { return false }
            return true
        }

        /**
         This function returns the HMAC for the message that consists of all parts passed into the `update` method. After calling this method you should not call `update` again.

         - Returns: an authenticator (HMAC) for the given multi-part message or `nil` if the HMAC cannot be calculated.
         */
        public func final() -> Bytes? {
            var output = Bytes(count: HMAC.HMACSHA512Bytes)
            guard .SUCCESS == crypto_auth_hmacsha512_final(&state, &output).exitCode else { return nil }
            return output
        }
    }

    public class MultiPartHMACSHA512256: MultiPartHMAC {
        private var state: crypto_auth_hmacsha512256_state

        init?(key: Bytes) {
            state = crypto_auth_hmacsha512256_state()
            guard .SUCCESS == crypto_auth_hmacsha512256_init(&state, key, key.count).exitCode else { return nil}
        }

        /**
         This function updates the HMAC by including another part of the message to be authenticated.

         - Parameter message: the message part

         - Returns: true if the given message part was included into the HMAC successfully, false otherwise.
         */
        public func update(message: Bytes) -> Bool {
            guard .SUCCESS == crypto_auth_hmacsha512256_update(&state, message, UInt64(message.count)).exitCode else { return false }
            return true
        }

        /**
         This function returns the HMAC for the message that consists of all parts passed into the `update` method. After calling this method you should not call `update` again.

         - Returns: an authenticator (HMAC) for the given multi-part message or `nil` if the HMAC cannot be calculated.
         */
        public func final() -> Bytes? {
            var output = Bytes(count: HMAC.HMACSHA512256Bytes)
            guard .SUCCESS == crypto_auth_hmacsha512256_final(&state, &output).exitCode else { return nil }
            return output
        }
    }

    /**
     This function can be used to create a HMAC for a multi-part (streamed) message. After initializing the MultiPartHMAC object by providing the hash algorithm and the key to be used the `update` method can be called anytime a new part of the message should be included into the authenticator. Finally the `final` method returns the HMAC. Afterwards you should not call `update` on that object again.

     - Parameter key: the key that is being used calculating the HMAC
     - Parameter alg: the hashing algorithm (SHA-256, SHA-512 or SHA-512-256)

     - Returns: an MultiPartHMAC object that can be used to include new parts of the message and return the final HMAC. If the MultiPartHMAC object cannot be initialized this method returns `nil`.
     */
    public func initMultiPartHMAC(key: Bytes, alg: Alg) -> MultiPartHMAC? {
        switch alg {
        case .sha256:
            return MultiPartHMACSHA256(key: key)
        case .sha512:
            return MultiPartHMACSHA512(key: key)
        case .sha512256:
            return MultiPartHMACSHA512256(key: key)
        }
    }
}
