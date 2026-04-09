import Clibsodium
import Foundation

public struct RandomBytes {
    public let SeedBytes = Int(randombytes_seedbytes())
}

public extension RandomBytes {
    /**
     Returns a `Bytes` object of length `length` containing an unpredictable sequence of bytes.

     - Parameter length: The number of bytes to generate.

     - Returns: The generated data.
     */
    func buf(length: Int) -> Bytes? {
        guard length >= 0 else { return nil }
        var output = Bytes(count: length)
        randombytes_buf(&output, length)
        return output
    }

    /**
     - Returns: An unpredictable value between 0 and 0xffffffff (included).
     */
    func random() -> UInt32 {
        randombytes_random()
    }

    /**
     Returns an unpredictable value between 0 and `upper_bound` (excluded). Unlike
     `randombytes_random() % upper_bound`, it does its best to guarantee a uniform distribution of
     the possible output values even when upper_bound is not a power of 2.

     - Parameter upperBound: The upper bound (excluded) of the returned value.

     - Returns: The unpredictable value.
     */
    func uniform(upperBound: UInt32) -> UInt32 {
        randombytes_uniform(upperBound)
    }

    /**
     Returns a deterministic stream of unbiased bits derived from a seed.

     - Parameter length: The number of bytes to generate.
     - Parameter seed: The seed.

     - Returns: The generated data.
     */
    func deterministic(length: Int, seed: Bytes) -> Bytes? {
        guard length >= 0,
              seed.count == SeedBytes,
              Int64(length) <= 0x40_0000_0000 as Int64
        else { return nil }

        var output = Bytes(count: length)
        randombytes_buf_deterministic(&output, length, seed)
        return output
    }
}

public extension RandomBytes {
    struct Generator: RandomNumberGenerator {
        private let sodium = Sodium()

        public init() {}

        public mutating func next() -> UInt64 {
            guard let bytes = sodium.randomBytes.buf(length: MemoryLayout<UInt64>.size) else {
                fatalError("Sodium Random Number Generator is broken")
            }

            return bytes.withUnsafeBytes { pointer in
                pointer.load(as: UInt64.self)
            }
        }
    }
}
