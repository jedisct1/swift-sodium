//
//  Version.swift
//  Sodium
//
//  Created by Frank on 13/07/2021.
//  Copyright © 2021 Frank Denis. All rights reserved.
//

import Clibsodium

public struct Lib {
    public let VersionString = String(validatingUTF8:sodium_version_string())!
    public let Major = Int(sodium_library_version_major())
    public let Minor = Int(sodium_library_version_minor())
}

public struct Version {
    public let lib = Lib()
}
