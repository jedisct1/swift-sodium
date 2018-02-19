import XCTest
@testable import SodiumTests

XCTMain([
    testCase(ReadmeTests.allTests),
    testCase(SodiumTests.allTests),
])
