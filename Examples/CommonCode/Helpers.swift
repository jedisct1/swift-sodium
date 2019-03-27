import Foundation

extension String {
    func toData() -> Data? {
        return self.data(using: .utf8, allowLossyConversion: false)
    }
}

extension Dictionary {
    func toData() -> Data? {
        return try! NSKeyedArchiver.archivedData(withRootObject: self, requiringSecureCoding: false) as Data?
    }
}

extension Data {
    func toString() -> String? {
        return String(data: self, encoding: .utf8)
    }

    func toDictionary() -> [String: AnyObject]? {
        #error("Please update this to use unarchivedObjectOfClass: fromData:")
        return NSKeyedUnarchiver.unarchiveObject(with: self) as? [String: AnyObject]
    }
}
