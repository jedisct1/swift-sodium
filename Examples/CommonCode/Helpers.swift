import Foundation

extension String {
    func toData() -> Data? {
        return self.data(using: .utf8, allowLossyConversion: false)
    }
}

extension Dictionary {
    func toData() -> Data? {
        return NSKeyedArchiver.archivedData(withRootObject: self) as Data?
    }
}

extension Data {
    func toString() -> String? {
        return String(data: self, encoding: .utf8)
    }

    func toDictionary() -> [String: AnyObject]? {
        return NSKeyedUnarchiver.unarchiveObject(with: self) as? [String: AnyObject]
    }
}
