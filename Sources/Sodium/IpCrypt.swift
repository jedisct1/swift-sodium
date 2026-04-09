import Clibsodium
import Foundation

public struct IpCrypt {
    public let deterministic = Deterministic()
    public let nd = Nd()
    public let ndx = Ndx()
    public let pfx = Pfx()
}

public extension IpCrypt {
    struct Deterministic {
        public let IpBytes = Int(crypto_ipcrypt_bytes())
        public typealias Key = Bytes
    }
}

extension IpCrypt.Deterministic: SecretKeyGenerator {
    public var KeyBytes: Int {
        Int(crypto_ipcrypt_keybytes())
    }

    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_ipcrypt_keygen
}

public extension IpCrypt.Deterministic {
    func encrypt(ip: Bytes, secretKey: Key) -> Bytes? {
        guard ip.count == IpBytes, secretKey.count == KeyBytes else { return nil }

        var out = Bytes(count: IpBytes)
        crypto_ipcrypt_encrypt(&out, ip, secretKey)
        return out
    }

    func decrypt(encrypted: Bytes, secretKey: Key) -> Bytes? {
        guard encrypted.count == IpBytes, secretKey.count == KeyBytes else { return nil }

        var out = Bytes(count: IpBytes)
        crypto_ipcrypt_decrypt(&out, encrypted, secretKey)
        return out
    }

    func encrypt(ip: String, secretKey: Key) -> String? {
        guard let ipBin = Utils().ip2bin(ip),
              let encrypted = encrypt(ip: ipBin, secretKey: secretKey) else { return nil }
        return Utils().bin2ip(encrypted)
    }

    func decrypt(encrypted: String, secretKey: Key) -> String? {
        guard let encryptedBin = Utils().ip2bin(encrypted),
              let decrypted = decrypt(encrypted: encryptedBin, secretKey: secretKey) else { return nil }
        return Utils().bin2ip(decrypted)
    }
}

public extension IpCrypt {
    struct Nd {
        public let InputBytes = Int(crypto_ipcrypt_nd_inputbytes())
        public let OutputBytes = Int(crypto_ipcrypt_nd_outputbytes())
        public let TweakBytes = Int(crypto_ipcrypt_nd_tweakbytes())
        public typealias Key = Bytes
        public typealias Tweak = Bytes
    }
}

extension IpCrypt.Nd: SecretKeyGenerator {
    public var KeyBytes: Int {
        Int(crypto_ipcrypt_nd_keybytes())
    }

    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_ipcrypt_keygen
}

public extension IpCrypt.Nd {
    func encrypt(ip: Bytes, tweak: Tweak, secretKey: Key) -> Bytes? {
        guard ip.count == InputBytes, tweak.count == TweakBytes, secretKey.count == KeyBytes else { return nil }

        var out = Bytes(count: OutputBytes)
        crypto_ipcrypt_nd_encrypt(&out, ip, tweak, secretKey)
        return out
    }

    func decrypt(encrypted: Bytes, secretKey: Key) -> Bytes? {
        guard encrypted.count == OutputBytes, secretKey.count == KeyBytes else { return nil }

        var out = Bytes(count: InputBytes)
        crypto_ipcrypt_nd_decrypt(&out, encrypted, secretKey)
        return out
    }

    func encrypt(ip: String, tweak: Tweak, secretKey: Key) -> String? {
        guard let ipBin = Utils().ip2bin(ip),
              let encrypted = encrypt(ip: ipBin, tweak: tweak, secretKey: secretKey) else { return nil }
        return Utils().bin2hex(encrypted)
    }

    func decrypt(encrypted: String, secretKey: Key) -> String? {
        guard let encryptedBin = Utils().hex2bin(encrypted),
              let decrypted = decrypt(encrypted: encryptedBin, secretKey: secretKey) else { return nil }
        return Utils().bin2ip(decrypted)
    }
}

public extension IpCrypt {
    struct Ndx {
        public let InputBytes = Int(crypto_ipcrypt_ndx_inputbytes())
        public let OutputBytes = Int(crypto_ipcrypt_ndx_outputbytes())
        public let TweakBytes = Int(crypto_ipcrypt_ndx_tweakbytes())
        public typealias Key = Bytes
        public typealias Tweak = Bytes
    }
}

extension IpCrypt.Ndx: SecretKeyGenerator {
    public var KeyBytes: Int {
        Int(crypto_ipcrypt_ndx_keybytes())
    }

    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_ipcrypt_ndx_keygen
}

public extension IpCrypt.Ndx {
    func encrypt(ip: Bytes, tweak: Tweak, secretKey: Key) -> Bytes? {
        guard ip.count == InputBytes, tweak.count == TweakBytes, secretKey.count == KeyBytes else { return nil }

        var out = Bytes(count: OutputBytes)
        crypto_ipcrypt_ndx_encrypt(&out, ip, tweak, secretKey)
        return out
    }

    func decrypt(encrypted: Bytes, secretKey: Key) -> Bytes? {
        guard encrypted.count == OutputBytes, secretKey.count == KeyBytes else { return nil }

        var out = Bytes(count: InputBytes)
        crypto_ipcrypt_ndx_decrypt(&out, encrypted, secretKey)
        return out
    }

    func encrypt(ip: String, tweak: Tweak, secretKey: Key) -> String? {
        guard let ipBin = Utils().ip2bin(ip),
              let encrypted = encrypt(ip: ipBin, tweak: tweak, secretKey: secretKey) else { return nil }
        return Utils().bin2hex(encrypted)
    }

    func decrypt(encrypted: String, secretKey: Key) -> String? {
        guard let encryptedBin = Utils().hex2bin(encrypted),
              let decrypted = decrypt(encrypted: encryptedBin, secretKey: secretKey) else { return nil }
        return Utils().bin2ip(decrypted)
    }
}

public extension IpCrypt {
    struct Pfx {
        public let IpBytes = Int(crypto_ipcrypt_pfx_bytes())
        public typealias Key = Bytes
    }
}

extension IpCrypt.Pfx: SecretKeyGenerator {
    public var KeyBytes: Int {
        Int(crypto_ipcrypt_pfx_keybytes())
    }

    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_ipcrypt_pfx_keygen
}

public extension IpCrypt.Pfx {
    func encrypt(ip: Bytes, secretKey: Key) -> Bytes? {
        guard ip.count == IpBytes, secretKey.count == KeyBytes else { return nil }

        var out = Bytes(count: IpBytes)
        crypto_ipcrypt_pfx_encrypt(&out, ip, secretKey)
        return out
    }

    func decrypt(encrypted: Bytes, secretKey: Key) -> Bytes? {
        guard encrypted.count == IpBytes, secretKey.count == KeyBytes else { return nil }

        var out = Bytes(count: IpBytes)
        crypto_ipcrypt_pfx_decrypt(&out, encrypted, secretKey)
        return out
    }

    func encrypt(ip: String, secretKey: Key) -> String? {
        guard let ipBin = Utils().ip2bin(ip),
              let encrypted = encrypt(ip: ipBin, secretKey: secretKey) else { return nil }
        return Utils().bin2ip(encrypted)
    }

    func decrypt(encrypted: String, secretKey: Key) -> String? {
        guard let encryptedBin = Utils().ip2bin(encrypted),
              let decrypted = decrypt(encrypted: encryptedBin, secretKey: secretKey) else { return nil }
        return Utils().bin2ip(decrypted)
    }
}
