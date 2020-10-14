import Foundation

extension String {
    func toData() -> Data? {
        return self.data(using: .utf8, allowLossyConversion: false)
    }
}

extension Dictionary {
    func toData() -> Data? {
        if #available(iOS 11.0, macOS 10.13, *, tvOS 11.0) {
            return try? NSKeyedArchiver.archivedData(withRootObject: self, requiringSecureCoding: false)
        } else {
            return NSKeyedArchiver.archivedData(withRootObject: self)
        }
    }
}

extension Data {
    func toString() -> String? {
        return String(data: self, encoding: .utf8)
    }

    func toDictionary() -> [String: AnyObject]? {
        if #available(iOS 9.0, *) {
            return try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(self) as? [String: AnyObject]
        } else {
            return NSKeyedUnarchiver.unarchiveObject(with: self) as? [String: AnyObject]
        }
    }
}
