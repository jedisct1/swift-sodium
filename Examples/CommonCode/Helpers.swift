import Foundation

extension String {
    func toData() -> Data? {
        data(using: .utf8, allowLossyConversion: false)
    }
}

extension Dictionary {
    func toData() -> Data? {
        try? JSONSerialization.data(withJSONObject: self, options: [])
    }
}

extension Data {
    func toString() -> String? {
        String(data: self, encoding: .utf8)
    }

    func toDictionary() -> [String: AnyObject]? {
        try? JSONSerialization.jsonObject(with: self, options: []) as? [String: AnyObject]
    }
}
