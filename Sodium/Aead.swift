import Foundation
import Clibsodium

public struct Aead {
    public let xchacha20poly1305ietf = XChaCha20Poly1305Ietf()
    
    public class XChaCha20Poly1305Ietf {
        public let KeyBytes = Int(crypto_aead_xchacha20poly1305_ietf_keybytes())
        public let NonceBytes = Int(crypto_aead_xchacha20poly1305_ietf_npubbytes())
        public let ABytes = Int(crypto_aead_xchacha20poly1305_ietf_abytes())
        
        public typealias Key = Data
        public typealias Nonce = Data
        public typealias MAC = Data
        
        /**
         Generates a shared secret key.
         
         - Returns: The generated key.
         */
        public func key() -> Key? {
            var secretKey = Data(count: KeyBytes)
            secretKey.withUnsafeMutableBytes { secretKeyPtr in
                crypto_aead_xchacha20poly1305_ietf_keygen(secretKeyPtr)
            }
            return secretKey
        }
        
        /**
         Generates an encryption nonce.
         
         - Returns: The generated nonce.
         */
        public func nonce() -> Nonce {
            let nonceLen = NonceBytes
            var nonce = Data(count: nonceLen)
            nonce.withUnsafeMutableBytes { noncePtr in
                randombytes_buf(noncePtr, nonceLen)
            }
            return nonce
        }
        
        /**
         Encrypts a message with a shared secret key.
         
         - Parameter message: The message to encrypt.
         - Parameter secretKey: The shared secret key.
         - Parameter additionalData: A typical use for these data is to authenticate version numbers, timestamps or monotonically increasing counters
         
         - Returns: A `Data` object containing the nonce and authenticated ciphertext.
         */
        public func encrypt(message: Data, secretKey: Key, additionalData: Data? = nil) -> Data? {
            guard let (authenticatedCipherText, nonce): (Data, Nonce) = encrypt(
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
        public func encrypt(message: Data, secretKey: Key, additionalData: Data? = nil) -> (authenticatedCipherText: Data, nonce: Nonce)? {
            guard secretKey.count == KeyBytes else {
                return nil
            }
            
            var authenticatedCipherText = Data(count: message.count + ABytes)
            var authenticatedCipherTextLen = Data()
            let nonce = self.nonce()
            let result: ExitCode

            if let additionalData = additionalData {
                result = authenticatedCipherText.withUnsafeMutableBytes { authenticatedCipherTextPtr in
                    authenticatedCipherTextLen.withUnsafeMutableBytes { authenticatedCipherTextLenPtr in
                        message.withUnsafeBytes { messagePtr in
                            additionalData.withUnsafeBytes { additionalDataPtr in
                                nonce.withUnsafeBytes { noncePtr in
                                    secretKey.withUnsafeBytes { secretKeyPtr in
                                        crypto_aead_xchacha20poly1305_ietf_encrypt(
                                            authenticatedCipherTextPtr,
                                            authenticatedCipherTextLenPtr,

                                            messagePtr,
                                            UInt64(message.count),

                                            additionalDataPtr,
                                            UInt64(additionalData.count),

                                            nil, noncePtr, secretKeyPtr
                                        ).exitCode
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                result = authenticatedCipherText.withUnsafeMutableBytes { authenticatedCipherTextPtr in
                    authenticatedCipherTextLen.withUnsafeMutableBytes { authenticatedCipherTextLenPtr in
                        message.withUnsafeBytes { messagePtr in
                            nonce.withUnsafeBytes { noncePtr in
                                secretKey.withUnsafeBytes { secretKeyPtr in
                                    crypto_aead_xchacha20poly1305_ietf_encrypt(
                                        authenticatedCipherTextPtr,
                                        authenticatedCipherTextLenPtr,

                                        messagePtr,
                                        UInt64(message.count),

                                        nil,
                                        0,

                                        nil, noncePtr, secretKeyPtr
                                    ).exitCode
                                }
                            }
                        }
                    }
                }
            }
            guard result == .SUCCESS else { return nil }
    
            return (authenticatedCipherText: authenticatedCipherText, nonce: nonce)
        }
        
        /**
         Decrypts a message with a shared secret key.
         
         - Parameter nonceAndAuthenticatedCipherText: A `Data` object containing the nonce and authenticated ciphertext.
         - Parameter secretKey: The shared secret key.
         - Parameter additionalData: Must be used same `Data` that was used to encrypt, if `Data` deferred will return nil
         
         - Returns: The decrypted message.
         */
        public func decrypt(nonceAndAuthenticatedCipherText: Data, secretKey: Key, additionalData: Data? = nil) -> Data? {
            guard nonceAndAuthenticatedCipherText.count >= ABytes + NonceBytes else {
                return nil
            }
            
            let nonce = nonceAndAuthenticatedCipherText[..<NonceBytes] as Nonce
            let authenticatedCipherText = nonceAndAuthenticatedCipherText[NonceBytes...]

            return decrypt(authenticatedCipherText: authenticatedCipherText, secretKey: secretKey, nonce: nonce, additionalData: additionalData)
        }
        
        /**
         Decrypts a message with a shared secret key.
         
         - Parameter authenticatedCipherText: A `Data` object containing authenticated ciphertext.
         - Parameter secretKey: The shared secret key.
         - Parameter additionalData: Must be used same `Data` that was used to encrypt, if `Data` deferred will return nil
         
         - Returns: The decrypted message.
         */
        public func decrypt(authenticatedCipherText: Data, secretKey: Key, nonce: Nonce, additionalData: Data? = nil) -> Data? {
            guard authenticatedCipherText.count >= ABytes else {
                return nil
            }
            
            var message = Data(count: authenticatedCipherText.count - ABytes)
            var messageLen = Data()
            let result: ExitCode
    
            if let additionalData = additionalData {
                result = message.withUnsafeMutableBytes { messagePtr in
                    messageLen.withUnsafeMutableBytes { messageLen in
                        authenticatedCipherText.withUnsafeBytes { cipherTextPtr in
                            additionalData.withUnsafeBytes { additionalDataPtr in
                                nonce.withUnsafeBytes { noncePtr in
                                    secretKey.withUnsafeBytes { secretKeyPtr in
                                        crypto_aead_xchacha20poly1305_ietf_decrypt(
                                            messagePtr,
                                            messageLen,
                                            
                                            nil,
                                            
                                            cipherTextPtr,
                                            UInt64(authenticatedCipherText.count),
                                            
                                            additionalDataPtr,
                                            UInt64(additionalData.count),
                                            
                                            noncePtr, secretKeyPtr
                                        ).exitCode
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                result = message.withUnsafeMutableBytes { messagePtr in
                    messageLen.withUnsafeMutableBytes { messageLen in
                        authenticatedCipherText.withUnsafeBytes { cipherTextPtr in
                            nonce.withUnsafeBytes { noncePtr in
                                secretKey.withUnsafeBytes { secretKeyPtr in
                                    crypto_aead_xchacha20poly1305_ietf_decrypt(
                                        messagePtr,
                                        messageLen,
                                        
                                        nil,
                                        
                                        cipherTextPtr,
                                        UInt64(authenticatedCipherText.count),
                                        
                                        nil,
                                        0,
                                        
                                        noncePtr, secretKeyPtr
                                    ).exitCode
                                }
                            }
                        }
                    }
                }
            }
    
            guard result == .SUCCESS else {
                return nil
            }
    
            return message
        }
    }
}
