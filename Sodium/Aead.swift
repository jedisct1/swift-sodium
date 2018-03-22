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
            var nonce = Data(count: NonceBytes)
            nonce.withUnsafeMutableBytes { noncePtr in
                randombytes_buf(noncePtr, nonce.count)
            }
            return nonce
        }
        
        public func encrypt(message: Data, additionalData: Data, secretKey: Key) -> Data? {
            let nonce = self.nonce()
            
            guard let authenticatedCipherText: Data = encrypt(message: message, additionalData: additionalData, nonce: nonce, secretKey: secretKey) else {
                return nil
            }
            var nonceAndAuthenticatedCipherText = nonce
            nonceAndAuthenticatedCipherText.append(authenticatedCipherText)

            return nonceAndAuthenticatedCipherText
        }
        
        public func decrypt(nonceAndAuthenticatedCipherText: Data, additionalData: Data, secretKey: Key) -> Data? {
            if nonceAndAuthenticatedCipherText.count < ABytes + NonceBytes {
                return nil
            }
            let nonce = nonceAndAuthenticatedCipherText.subdata(in: 0..<NonceBytes) as Nonce
            let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdata(in: NonceBytes..<nonceAndAuthenticatedCipherText.count)
            
            return decrypt(cipherText: authenticatedCipherText, additionalData: additionalData, nonce: nonce, secretKey: secretKey)
        }
        
        public func encrypt(message: Data, additionalData: Data, nonce: Nonce, secretKey: Key) -> Data? {
            guard nonce.count == NonceBytes else {
                return nil
            }
            
            guard secretKey.count == KeyBytes else {
                return nil
            }
            
            var authenticatedCipherText = Data(count: message.count + ABytes)
            var cipherTextLen = Data()
    
            let result = authenticatedCipherText.withUnsafeMutableBytes { cipherTextPtr in
                cipherTextLen.withUnsafeMutableBytes { cipherTextLen in
                    message.withUnsafeBytes { messagePtr in
                        additionalData.withUnsafeBytes { additionalDataPtr in
                            nonce.withUnsafeBytes { noncePtr in
                                secretKey.withUnsafeBytes { secretKeyPtr in
                                    crypto_aead_xchacha20poly1305_ietf_encrypt(
                                        UnsafeMutablePointer<UInt8>(cipherTextPtr),
                                        UnsafeMutablePointer<UInt64>(cipherTextLen),
    
                                        UnsafePointer<UInt8>(messagePtr),
                                        UInt64(message.count),
    
                                        UnsafePointer<UInt8>(additionalDataPtr),
                                        UInt64(additionalData.count),
    
                                        nil, noncePtr, secretKeyPtr
                                    )
                                }
                            }
                        }
                    }
                }
            }
    
            guard result == 0 else {
                return nil
            }
    
            return authenticatedCipherText
        }
        
        public func decrypt(cipherText: Data, additionalData: Data, nonce: Nonce, secretKey: Key) -> Data? {
            guard nonce.count == NonceBytes else {
                return nil
            }
            
            guard secretKey.count == KeyBytes else {
                return nil
            }
            
            guard cipherText.count > ABytes else {
                return nil
            }
            
            var decrypted = Data(count: cipherText.count - ABytes)
            var decryptedLen = Data()
    
            let result = decrypted.withUnsafeMutableBytes { decryptedPtr in
                decryptedLen.withUnsafeMutableBytes { decryptedLen in
                    cipherText.withUnsafeBytes { cipherTextPtr in
                        additionalData.withUnsafeBytes { additionalDataPtr in
                            nonce.withUnsafeBytes { noncePtr in
                                secretKey.withUnsafeBytes { secretKeyPtr in
                                    crypto_aead_xchacha20poly1305_ietf_decrypt(
                                        UnsafeMutablePointer<UInt8>(decryptedPtr),
                                        UnsafeMutablePointer<UInt64>(decryptedLen),
    
                                        nil,
    
                                        UnsafePointer<UInt8>(cipherTextPtr),
                                        UInt64(cipherText.count),
    
                                        UnsafePointer<UInt8>(additionalDataPtr),
                                        UInt64(additionalData.count),
    
                                        noncePtr, secretKeyPtr
                                    )
                                }
                            }
                        }
                    }
                }
            }
    
            guard result == 0 else {
                return nil
            }
    
            return decrypted
        }
    }
}
