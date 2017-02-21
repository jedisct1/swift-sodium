//
//  KeyExchange.swift
//  Sodium
//
//  Created by Andreas Ganske on 20.02.17.
//  Copyright © 2017 Frank Denis. All rights reserved.
//

import Foundation

public class KeyExchange {
    public let PublicKeyBytes = Int(crypto_box_publickeybytes())
    public let SecretKeyBytes = Int(crypto_box_secretkeybytes())
    public let SecretBytes = Int(crypto_scalarmult_bytes())
    public let Bytes = Int(crypto_hash_bytes())
    
    /**
     This function can be used to compute a shared secret given a user's secret key and another user's public key.
     See https://download.libsodium.org/doc/advanced/scalar_multiplication.html for more details.
     
     - Parameter secretKey: The secret key to use in diffie hellman key exchange
     - Parameter publicKey: The public key used in conjunction with the other public key to hash the computed secret
     - Parameter otherPublicKey: The other user's public key to use in diffie hellman key exchange
     
     - Returns: The computed shared secret
     */
    public func diffieHellman(secretKey: Box.SecretKey, publicKey: Box.PublicKey, otherPublicKey: Box.PublicKey) -> Data? {
        
        if secretKey.count != SecretKeyBytes || otherPublicKey.count != PublicKeyBytes {
            return nil
        }
        
        var output = Data(count: SecretBytes)
        var result: Int32 = -1
        
        result = output.withUnsafeMutableBytes { outputPtr in
            return secretKey.withUnsafeBytes { secretKeyPtr in
                return otherPublicKey.withUnsafeBytes { otherPublicKeyPtr in
                    return crypto_scalarmult(outputPtr, secretKeyPtr, otherPublicKeyPtr)
                }
            }
        }
        
        if result != 0 {
            return nil
        }
        
        // Don't use the result yet because the number of possible keys is limited to the group size (≈2^252), and the key distribution is not uniform. So we use h( ouput || pk1 || pk2) as recommended by https://download.libsodium.org/doc/advanced/scalar_multiplication.html
        var bytes = Data(count: Bytes)
        
        guard let stream = GenericHash.Stream(key: nil, outputLength: bytes.count) else {
            return nil
        }
        
        // We have to choose in which order the public keys are concatenated, so we order them lexicographically (comparing byte by byte)
        let publicKeys = [publicKey, otherPublicKey].sorted(by: { (lhs, rhs) in
            return lhs.lexicographicallyPrecedes(rhs)
        })
        
        if !stream.update(input: output) { return nil }
        if !stream.update(input: publicKeys[0]) { return nil }
        if !stream.update(input: publicKeys[1]) { return nil }
        
        return stream.final()
    }
}
