//
//  Helpers.swift
//  Sodium
//
//  Created by RamaKrishna Mallireddy on 19/04/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Foundation

extension String {
    func toData() -> NSData? {
        return self.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
    }
}

extension Dictionary {
    func toData() -> NSData? {
        return NSKeyedArchiver.archivedDataWithRootObject(self as! AnyObject)
    }
}

extension NSData {
    func toString() -> String? {
        return (NSString(data: self, encoding: NSUTF8StringEncoding) as! String)
    }
    
    func toDictionary() -> [String: AnyObject]? {
        return NSKeyedUnarchiver.unarchiveObjectWithData(self) as? [String: AnyObject]
    }
}