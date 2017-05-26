//
//  ECDH.swift
//  Sodium
//
//  Created by Jonas Hauser on 26.05.17.
//  Copyright © 2017 Jonas Hauser. All rights reserved.
//

import Foundation
import libsodium

public class ECDH {
    public let Bytes = Int(crypto_scalarmult_bytes())
    public let ScalarBytes = Int(crypto_scalarmult_scalarbytes())

    public typealias Key = Data
    
    public struct DHKey {
        public let publicKey: Key
        public let secretKey: Key
        
        public init(publicKey: Key, secretKey: Key) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }
    
    public func keyPair() -> DHKey? {
        var secretKey = Data(count: Bytes)
        secretKey.withUnsafeMutableBytes { secretKeyPtr in
            randombytes_buf(secretKeyPtr, secretKey.count)
        }
        
        var publicKey = Data(count: Bytes)
        let result = publicKey.withUnsafeMutableBytes { publicKeyPtr in
            return secretKey.withUnsafeBytes { secretKeyPtr in
                return crypto_scalarmult_base(publicKeyPtr, secretKeyPtr)
            }
        }
        
        if result != 0 {
            return nil
        }
        
        return DHKey(publicKey: publicKey, secretKey: secretKey)
    }
    
    public func secret(secretKey: Key, publicKey: Key) -> Key? {
        guard secretKey.count == Bytes, publicKey.count == Bytes else { return nil }
        
        var sharedSecret = Data(count: Bytes)
        
        let result = sharedSecret.withUnsafeMutableBytes { ssPtr in
            return secretKey.withUnsafeBytes { skPtr in
                return publicKey.withUnsafeBytes { pkPtr in
                    return crypto_scalarmult(ssPtr, skPtr, pkPtr)
                }
            }
        }
        
        if result != 0 {
            return nil
        }
        
        return sharedSecret
    }
    
}
