import Foundation
import Clibsodium

public struct Stream {
    public let Primitive = String(validatingUTF8: crypto_stream_primitive())
}

extension Stream {
    /**
     XOR the input with a key stream derived from a secret key and a nonce.
     Applying the same operation twice outputs the original input.
     No authentication tag is added to the output. The data can be tampered with; an adversary can flip arbitrary bits.
     In order to encrypt data using a secret key, the SecretBox class is likely to be what you are looking for.
     In order to generate a deterministic stream out of a seed, the RandomBytes.deterministic_rand() function is likely to be what you need.

     - Parameter input: Input data
     - Parameter nonce: Nonce
     - Parameter secretKey: The secret key

     -  Returns: input XOR keystream(secretKey, nonce)
     */
    public func xor(input: BytesRepresentable, nonce: Nonce, secretKey: Key) -> BytesContainer? {
        guard secretKey.count == KeyBytes, nonce.count == NonceBytes else { return nil }

        let input = input.bytes
        var output = BytesContainer(count: input.count)
        guard .SUCCESS == crypto_stream_xor (
            &output.bytes,
            input, UInt64(input.count),
            nonce.bytes,
            secretKey.bytes
        ).exitCode else { return nil }

        return output
    }

    /**
     XOR the input with a key stream derived from a secret key and a random nonce.
     Applying the same operation twice outputs the original input.
     No authentication tag is added to the output. The data can be tampered with; an adversary can flip arbitrary bits.
     In order to encrypt data using a secret key, the SecretBox class is likely to be what you are looking for.
     In order to generate a deterministic stream out of a seed, the RandomBytes.deterministic_rand() function is likely to be what you need.

     - Parameter input: Input data
     - Parameter nonce: Nonce
     - Parameter secretKey: The secret key

     -  Returns: (input XOR keystream(secretKey, nonce), nonce)
     */
    public func xor(input: BytesRepresentable, secretKey: Key) -> (output:BytesContainer, nonce: Nonce)? {
        let nonce = self.nonce()

        guard let output: BytesContainer = xor(
            input: input,
            nonce: nonce,
            secretKey: secretKey
        ) else { return nil }

        return (output: output, nonce: nonce)
    }
}

extension Stream: NonceGenerator {
    public typealias Nonce = BytesContainer
    public var NonceBytes: Int { return Int(crypto_secretbox_noncebytes()) }
}

extension Stream: SecretKeyGenerator {
    public typealias Key = BytesContainer
    public var KeyBytes: Int { return Int(crypto_secretbox_keybytes()) }

    static let keygen: (_ k: UnsafeMutablePointer<UInt8>) -> Void = crypto_stream_keygen
}
