import Clibsodium
import Foundation

public struct GenericHash {
    public let BytesMin = Int(crypto_generichash_bytes_min())
    public let BytesMax = Int(crypto_generichash_bytes_max())
    public let Bytes = Int(crypto_generichash_bytes())
    public let KeyBytesMin = Int(crypto_generichash_keybytes_min())
    public let KeyBytesMax = Int(crypto_generichash_keybytes_max())

    public let Primitive = String(validatingUTF8: crypto_generichash_primitive())
}

public extension GenericHash {
    class Stream {
        private var state: UnsafeMutableRawBufferPointer
        private var opaqueState: OpaquePointer
        public var outputLength: Int = 0

        init?(key: Bytes?, outputLength: Int) {
            state = UnsafeMutableRawBufferPointer.allocate(byteCount: crypto_generichash_statebytes(), alignment: 64)
            guard state.baseAddress != nil else { return nil }
            opaqueState = OpaquePointer(state.baseAddress!)
            guard crypto_generichash_init(
                opaqueState,
                key, key?.count ?? 0,
                outputLength
            ).exitCode == .SUCCESS else { return nil }

            self.outputLength = outputLength
        }

        deinit {
            state.deallocate()
        }
    }
}

public extension GenericHash {
    /**
     Computes a fixed-length fingerprint for an arbitrary long message. A key can also be specified. A message will always have the same fingerprint for a given key, but different keys used to hash the same message are very likely to produce distinct fingerprints.

     - Parameter message: The message from which to compute the fingerprint.
     - Parameter key: Optional key to use while computing the fingerprint.

     - Returns: The computed fingerprint.
     */
    func hash(message: Bytes, key: Bytes? = nil) -> Bytes? {
        hash(message: message, key: key, outputLength: Bytes)
    }

    /**
     Computes a fixed-length fingerprint for an arbitrary long message. A message will always have the same fingerprint for a given key, but different keys used to hash the same message are very likely to produce distinct fingerprints.

     - Parameter message: The message from which to compute the fingerprint.
     - Parameter key: The key to use while computing the fingerprint.
     - Parameter outputLength: Desired length of the computed fingerprint.

     - Returns: The computed fingerprint.
     */
    func hash(message: Bytes, key: Bytes?, outputLength: Int) -> Bytes? {
        var output = [UInt8](count: outputLength)

        guard crypto_generichash(
            &output, outputLength,
            message, UInt64(message.count),
            key, key?.count ?? 0
        ).exitCode == .SUCCESS else { return nil }

        return output
    }

    /**
     Computes a fixed-length fingerprint for an arbitrary long message.

     - Parameter message: The message from which to compute the fingerprint.
     - Parameter outputLength: Desired length of the computed fingerprint.

     - Returns: The computed fingerprint.
     */
    func hash(message: Bytes, outputLength: Int) -> Bytes? {
        hash(message: message, key: nil, outputLength: outputLength)
    }
}

public extension GenericHash {
    /**
     Initializes a `Stream` object to compute a fixed-length fingerprint for an incoming stream of data. Particular data will always have the same fingerprint for a given key, but different keys used to hash the same data are very likely to produce distinct fingerprints.

     - Parameter key: Optional key to use while computing the fingerprint.

     - Returns: The initialized `Stream`.
     */
    func initStream(key: Bytes? = nil) -> Stream? {
        Stream(key: key, outputLength: Bytes)
    }

    /**
     Initializes a `Stream` object to compute a fixed-length fingerprint for an incoming stream of data. Particular data will always have the same fingerprint for a given key, but different keys used to hash the same data are very likely to produce distinct fingerprints.

     - Parameter key: Optional key to use while computing the fingerprint.
     - Parameter outputLength: Desired length of the computed fingerprint.

     - Returns: The initialized `Stream`.
     */
    func initStream(key: Bytes?, outputLength: Int) -> Stream? {
        Stream(key: key, outputLength: outputLength)
    }

    /**
     Initializes a `Stream` object to compute a fixed-length fingerprint for an incoming stream of data.

     - Parameter outputLength: Desired length of the computed fingerprint.

     - Returns: The initialized `Stream`.
     */
    func initStream(outputLength: Int) -> Stream? {
        Stream(key: nil, outputLength: outputLength)
    }
}

public extension GenericHash.Stream {
    /**
     Updates the hash stream with incoming data to contribute to the computed fingerprint.

     - Parameter input: The incoming stream data.

     - Returns: `true` if the data was consumed successfully.
     */
    @discardableResult
    func update(input: Bytes) -> Bool {
        crypto_generichash_update(
            opaqueState,
            input, UInt64(input.count)
        ).exitCode == .SUCCESS
    }

    /**
     Signals that the incoming stream of data is complete and triggers computation of the resulting fingerprint.

     - Returns: The computed fingerprint.
     */
    func final() -> Bytes? {
        let outputLen = outputLength
        var output = [UInt8](count: outputLen)
        guard crypto_generichash_final(
            opaqueState,
            &output, outputLen
        ).exitCode == .SUCCESS else { return nil }

        return output
    }
}

extension GenericHash: SecretKeyGenerator {
    public var KeyBytes: Int {
        Int(crypto_generichash_keybytes())
    }

    public typealias Key = Bytes

    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_generichash_keygen
}
