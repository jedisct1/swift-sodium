import Foundation
import Clibsodium

public class Advanced {
}

// Diffie-Hellman
public extension Advanced {
    
    /**
     Scalar multiplication of elliptic curve points.
     
     - Parameter n: typically a secret key.
     - Parameter p: typically a public key
     
     - Returns: typically a shared secret
     */
    
    public func scalarMult(n: Box.SecretKey, p: Box.PublicKey) -> Bytes? {
        var q = Bytes(count: Int(crypto_scalarmult_SCALARBYTES))
        guard .SUCCESS == crypto_scalarmult(&q, n, p).exitCode else { return nil }
        return q
    }
    
}

// Ed25519 to Curve25519
public extension Advanced {
    
    /**
     Converts from Ed25519 key to Curve25519 key
     
     - Parameter sk: the secret key in Ed25519 format
     
     - Returns: the secret key in Curve25519 format
     */
    
    public func toCurve25519(sk: Sign.SecretKey) -> Box.SecretKey? {
        var r = Bytes(count: Int(crypto_sign_SECRETKEYBYTES))
        guard .SUCCESS == crypto_sign_ed25519_sk_to_curve25519(&r, sk).exitCode else { return nil }
        return r
    }
    
    /**
     Converts from Ed25519 key to Curve25519 key
     
     - Parameter pk: the public key in Ed25519 format
     
     - Returns: the public key in Curve25519 format
     */
    
    public func toCurve25519(pk: Sign.PublicKey) -> Box.PublicKey? {
        var r = Bytes(count: Int(crypto_sign_PUBLICKEYBYTES))
        guard .SUCCESS == crypto_sign_ed25519_pk_to_curve25519(&r, pk).exitCode else { return nil }
        return r
    }
    
}

// SHA-2
public extension Advanced {
    
    /**
     A single-part SHA-256 calculation
 
     - Parameter input: raw data
     
     - Returns: a SHA256 digest
     */
    
    public func SHA256(_ input: Bytes) -> Bytes? {
        
        var out = Bytes(count: Int(crypto_hash_sha256_BYTES))
        guard .SUCCESS == crypto_hash_sha256(&out, input, UInt64(input.count)).exitCode else { return nil }
        return out
    }
    
    /**
     A single-part SHA-512 calculation
     
     - Parameter input: raw data
     
     - Returns: a SHA512 digest
     */
    
    public func SHA512(_ input: Bytes) -> Bytes? {
        
        var out = Bytes(count: Int(crypto_hash_sha512_BYTES))
        guard .SUCCESS == crypto_hash_sha512(&out, input, UInt64(input.count)).exitCode else { return nil }
        return out
    }
}
