import XCTest
import CVaporBcrypt
import Vapor

final class BcryptTests: XCTestCase {
    // MARK: - Original Base Functionality Tests
    
    func testVersion() throws {
        let digest = try Bcrypt.hash("foo", cost: 6)
        XCTAssert(digest.hasPrefix("$2b$06$"))
    }

    func testFail() throws {
        let digest = try Bcrypt.hash("foo", cost: 6)
        let res = try Bcrypt.verify("bar", created: digest)
        XCTAssertEqual(res, false)
    }

    func testInvalidMinCost() throws {
        XCTAssertThrowsError(try Bcrypt.hash("foo", cost: 1))
    }

    func testInvalidMaxCost() throws {
        XCTAssertThrowsError(try Bcrypt.hash("foo", cost: 32))
    }

    func testInvalidSalt() throws {
        XCTAssertThrowsError(try Bcrypt.verify("", created: "foo")) {
            XCTAssert($0 is BcryptError)
        }
    }

    func testVerify() throws {
        for (desired, message) in tests {
            let result = try Bcrypt.verify(message, created: desired)
            XCTAssert(result, "\(message): did not match \(desired)")
        }
    }

    func testOnlineVapor() throws {
        let result = try Bcrypt.verify("vapor", created: "$2a$10$e.qg8zwKLHu3ur5rPF97ouzCJiJmZ93tiwNekDvTQfuhyu97QaUk.")
        XCTAssert(result, "verification failed")
    }
    
    // MARK: - Salt Extraction Tests
    
    struct SaltTestCase {
        let hash: String
        let expectedSalt: String?
        let shouldSucceed: Bool
        let description: String
    }
    
    let validSaltTestCases: [SaltTestCase] = [
        SaltTestCase(
            hash: "$2b$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.",
            expectedSalt: "$2b$06$DCq7YPn5Rq63x1Lad4cll",
            shouldSucceed: true,
            description: "Empty string hash from test suite"
        ),
        SaltTestCase(
            hash: "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe",
            expectedSalt: "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
            shouldSucceed: true,
            description: "Single character hash from test suite"
        ),
        SaltTestCase(
            hash: "$2y$11$kHM/VXmCVsGXDGIVu9mD8eY/uEYI.Nva9sHgrLYuLzr0il28DDOGO",
            expectedSalt: "$2y$11$kHM/VXmCVsGXDGIVu9mD8e",
            shouldSucceed: true,
            description: "Vapor3 hash from test suite"
        )
    ]
    
    let invalidSaltTestCases: [SaltTestCase] = [
        SaltTestCase(
            hash: "invalid_hash",
            expectedSalt: nil,
            shouldSucceed: false,
            description: "Invalid format"
        ),
        SaltTestCase(
            hash: "$2x$08$abcdefghijklmnop",
            expectedSalt: nil,
            shouldSucceed: false,
            description: "Invalid version"
        ),
        SaltTestCase(
            hash: "$2a$99$abcdefghijklmnop",
            expectedSalt: nil,
            shouldSucceed: false,
            description: "Invalid cost factor"
        )
    ]
    
    // MARK: - Basic Salt Extraction Tests
    
    func testValidSaltExtraction() throws {
        for testCase in validSaltTestCases {
            let salt = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_SALTSPACE))
            defer { salt.deallocate() }
            
            let result = testCase.hash.withCString { hashPtr in
                vapor_bcrypt_extractsalt(hashPtr, salt, Int(BCRYPT_SALTSPACE))
            }
            
            XCTAssertEqual(result, 0, "Salt extraction should succeed for \(testCase.description)")
            
            let extractedSalt = String(cString: salt)
          print(extractedSalt)
            XCTAssertEqual(extractedSalt, testCase.expectedSalt,
                          "Extracted salt should match expected for \(testCase.description)")
        }
    }
    
    func testInvalidSaltExtraction() {
        for testCase in invalidSaltTestCases {
            let salt = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_SALTSPACE))
            defer { salt.deallocate() }
            
            let result = testCase.hash.withCString { hashPtr in
                vapor_bcrypt_extractsalt(hashPtr, salt, Int(BCRYPT_SALTSPACE))
            }
            
            XCTAssertEqual(result, -1, "Salt extraction should fail for \(testCase.description)")
        }
    }
    
    // MARK: - Edge Cases and Error Handling
    
    func testNullInputHandling() {
        let salt = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_SALTSPACE))
        defer { salt.deallocate() }
        
        let result = vapor_bcrypt_extractsalt(nil, salt, Int(BCRYPT_SALTSPACE))
        XCTAssertEqual(result, -1, "Should fail with nil input")
    }
    
    func testBufferOverflow() {
        let smallBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: 10)
        defer { smallBuffer.deallocate() }
        
        let result = "$2b$08$LrmaIX5x4TRtAwEfwJZa1.etJ3LGGE1pkGNE7rNonbYrbc.4tL8ba"
            .withCString { hashPtr in
                vapor_bcrypt_extractsalt(hashPtr, smallBuffer, 10)
            }
        
        XCTAssertEqual(result, -1, "Should fail with buffer too small")
    }
    
    func testEdgeCases() {
        let salt = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_SALTSPACE))
        defer { salt.deallocate() }
        
        // Test empty string
        let emptyResult = "".withCString { hashPtr in
            vapor_bcrypt_extractsalt(hashPtr, salt, Int(BCRYPT_SALTSPACE))
        }
        XCTAssertEqual(emptyResult, -1, "Should fail with empty string")
        
        // Test very long input
        let longString = String(repeating: "a", count: 1000)
        let longResult = longString.withCString { hashPtr in
            vapor_bcrypt_extractsalt(hashPtr, salt, Int(BCRYPT_SALTSPACE))
        }
        XCTAssertEqual(longResult, -1, "Should fail with very long input")
    }
    
    // MARK: - Version-Specific Tests
    
    func testAllVersions() throws {
        let testCases: [(hash: String, expectedSalt: String)] = [
            // $2$ - Original (Note: rarely used)
            ("$2$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
             "$2$05$CCCCCCCCCCCCCCCCCCCCC"),
            
            // $2a$ - First revision
            ("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
             "$2a$05$CCCCCCCCCCCCCCCCCCCCC"),
            
            // $2y$ - crypt_blowfish fixed version
            ("$2y$11$kHM/VXmCVsGXDGIVu9mD8eY/uEYI.Nva9sHgrLYuLzr0il28DDOGO",
             "$2y$11$kHM/VXmCVsGXDGIVu9mD8e"),
            
            // $2b$ - OpenBSD current version
            ("$2b$08$LrmaIX5x4TRtAwEfwJZa1.etJ3LGGE1pkGNE7rNonbYrbc.4tL8ba",
             "$2b$08$LrmaIX5x4TRtAwEfwJZa1"),
            
            // $2x$ - crypt_blowfish potentially buggy
            ("$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
             "$2x$05$CCCCCCCCCCCCCCCCCCCCC")
        ]
        
        for testCase in testCases {
            let salt = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_SALTSPACE))
            defer { salt.deallocate() }
            
            let result = testCase.hash.withCString { hashPtr in
                vapor_bcrypt_extractsalt(hashPtr, salt, Int(BCRYPT_SALTSPACE))
            }
            
            XCTAssertEqual(result, 0, "Salt extraction should succeed for hash: \(testCase.hash)")
            
            let extractedSalt = String(cString: salt)
            XCTAssertEqual(extractedSalt, testCase.expectedSalt,
                          "Extracted salt should match expected for hash: \(testCase.hash)")
            
            // Calculate expected length based on format
            let expectedLength = testCase.hash.hasPrefix("$2$") ? 27 : 28
            XCTAssertEqual(extractedSalt.count, expectedLength,
                          "Salt length should be \(expectedLength) characters for hash: \(testCase.hash)")
        }
    }
    
    func testSaltFormat() throws {
        let validFormats = [
            "$2$", "$2a$", "$2b$", "$2x$", "$2y$"
        ]
        
        for format in validFormats {
            let hash = "\(format)05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
            let expectedSalt = "\(format)05$CCCCCCCCCCCCCCCCCCCCC"
            
            let salt = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_SALTSPACE))
            defer { salt.deallocate() }
            
            let result = hash.withCString { hashPtr in
                vapor_bcrypt_extractsalt(hashPtr, salt, Int(BCRYPT_SALTSPACE))
            }
            
            XCTAssertEqual(result, 0, "Salt extraction should succeed for format: \(format)")
            
            let extractedSalt = String(cString: salt)
            XCTAssertEqual(extractedSalt, expectedSalt,
                          "Extracted salt should match expected for format: \(format)")
            
            XCTAssertTrue(extractedSalt.hasPrefix(format),
                         "Salt should start with correct format: \(format)")
            
            let expectedLength = format == "$2$" ? 27 : 28
            XCTAssertEqual(extractedSalt.count, expectedLength,
                         "Salt length should be \(expectedLength) characters for format: \(format)")
        }
    }
    
    // MARK: - Integration Tests
    
    func testFullHashCycle() throws {
        let password = "test_password"
        let hash = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_HASHSPACE))
        let extractedSalt = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_SALTSPACE))
        defer {
            hash.deallocate()
            extractedSalt.deallocate()
        }
        
        // First hash generation
        let result1 = password.withCString { keyPtr in
            "$2b$08$abcdefghijklmnopqrstuv".withCString { saltPtr in
                vapor_bcrypt_hashpass(keyPtr, saltPtr, hash, Int(BCRYPT_HASHSPACE))
            }
        }
        XCTAssertEqual(result1, 0, "First hash generation should succeed")
        
        // Extract salt
        let result2 = vapor_bcrypt_extractsalt(hash, extractedSalt, Int(BCRYPT_SALTSPACE))
        XCTAssertEqual(result2, 0, "Salt extraction should succeed")
        
        // Generate second hash with extracted salt
        let hash2 = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_HASHSPACE))
        defer { hash2.deallocate() }
        
        let result3 = password.withCString { keyPtr in
            vapor_bcrypt_hashpass(keyPtr, extractedSalt, hash2, Int(BCRYPT_HASHSPACE))
        }
        XCTAssertEqual(result3, 0, "Second hash generation should succeed")
        
        // Compare hashes
        let firstHash = String(cString: hash)
        let secondHash = String(cString: hash2)
        XCTAssertEqual(firstHash, secondHash, "Hashes should match after full cycle")
    }
    
    func testSaltExtractionWithVerify() throws {
        for (hash, message) in tests {
            let salt = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_SALTSPACE))
            defer { salt.deallocate() }
            
            let result = hash.withCString { hashPtr in
                vapor_bcrypt_extractsalt(hashPtr, salt, Int(BCRYPT_SALTSPACE))
            }
            XCTAssertEqual(result, 0, "Salt extraction should succeed for hash: \(hash)")
            
            let extractedSalt = String(cString: salt)
            
            let hash2 = UnsafeMutablePointer<Int8>.allocate(capacity: Int(BCRYPT_HASHSPACE))
            defer { hash2.deallocate() }
            
            let result2 = message.withCString { messagePtr in
                vapor_bcrypt_hashpass(messagePtr, extractedSalt, hash2, Int(BCRYPT_HASHSPACE))
            }
            XCTAssertEqual(result2, 0, "Hash generation with extracted salt should succeed")
            
            let newHash = String(cString: hash2)
            let verifyResult = try Bcrypt.verify(message, created: newHash)
            XCTAssertTrue(verifyResult, "Verification should succeed with newly generated hash")
        }
    }
}

// MARK: - Test Data
private let tests: [(String, String)] = [
    ("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "U*U"),
    ("$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK", "U*U*"),
    ("$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a", "U*U*U"),
    ("$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored"),
    ("$2a$04$TI13sbmh3IHnmRepeEFoJOkVZWsn5S1O8QOwm8ZU5gNIpJog9pXZm", "vapor"),
    ("$2y$11$kHM/VXmCVsGXDGIVu9mD8eY/uEYI.Nva9sHgrLYuLzr0il28DDOGO", "Vapor3"),
    ("$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", ""),
    ("$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe", "a"),
    ("$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i", "abc"),
    ("$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC", "abcdefghijklmnopqrstuvwxyz"),
    ("$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"),
]
