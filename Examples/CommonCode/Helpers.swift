import Foundation

extension String {
    func toData() -> Data? {
        return self.data(using: .utf8, allowLossyConversion: false)
    }
}

extension Dictionary {
    func toData() -> Data? {
        return try? JSONSerialization.data(withJSONObject: self, options: [])
    }
}

extension Data {
    func toString() -> String? {
        return String(data: self, encoding: .utf8)
    }

    func toDictionary() -> [String: AnyObject]? {
        return try? JSONSerialization.jsonObject(with: self, options: []) as? [String: AnyObject]
    }
}
