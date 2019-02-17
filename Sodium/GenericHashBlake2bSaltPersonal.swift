//
//  GenericHashBlake2bSaltPersonal.swift
//  Sodium
//
//  Created by Jonas Hauser on 17.02.19.
//  Copyright © 2019 Frank Denis. All rights reserved.
//  

import Foundation
import Clibsodium

public struct GenericHashBlake2bSaltPersonal {
    public let BytesMin = Int(crypto_generichash_blake2b_bytes_min())
    public let BytesMax = Int(crypto_generichash_blake2b_bytes_max())
    public let Bytes = Int(crypto_generichash_blake2b_bytes())
    public let KeyBytesMin = Int(crypto_generichash_blake2b_keybytes_min())
    public let KeyBytesMax = Int(crypto_generichash_blake2b_keybytes_max())
    //public let KeyBytes = Int(crypto_generichash_blake2b_keybytes())
    //public let StateBytes = Int(crypto_generichash_blake2b_statebytes())
    
    public let SaltBytes = Int(crypto_generichash_blake2b_saltbytes());
    public let PersonalBytes = Int(crypto_generichash_blake2b_personalbytes());
}

extension GenericHashBlake2bSaltPersonal {
    public class Stream {
        private var state: crypto_generichash_blake2b_state
        public var outputLength: Int = 0
        
        init?(key: Bytes?, salt: Bytes, personal: Bytes, outputLength: Int) {
            state = crypto_generichash_blake2b_state()
            
            guard .SUCCESS == crypto_generichash_blake2b_init_salt_personal(
                &state,
                key, key?.count ?? 0,
                outputLength,
                salt,
                personal
                ).exitCode else { return nil }
            
            self.outputLength = outputLength
        }
    }
}

extension GenericHashBlake2bSaltPersonal {
    /**
     * blake2b_salt_personal
     */
    public func hash(message: Bytes, key: Bytes? = nil, salt: Bytes, personal: Bytes) -> Bytes? {
        return hash(message: message, key: key, salt: salt, personal: personal, outputLength: Bytes)
    }
    
    /**
     * blake2b_salt_personal
     */
    public func hash(message: Bytes, key: Bytes?, salt: Bytes, personal: Bytes, outputLength: Int) -> Bytes? {
        var output = Array<UInt8>(count: outputLength)
        
        guard .SUCCESS == crypto_generichash_blake2b_salt_personal(
            &output, outputLength,
            message, UInt64(message.count),
            key, key?.count ?? 0,
            salt,
            personal
            ).exitCode else { return nil }
        
        return output
    }
    
    /**
     * blake2b_salt_personal
     */
    public func hash(message: Bytes, salt: Bytes, personal: Bytes, outputLength: Int) -> Bytes? {
        return hash(message: message, key: nil, salt: salt, personal: personal, outputLength: outputLength)
    }
}

extension GenericHashBlake2bSaltPersonal {
    /**
     * blake2b_salt_personal
     */
    public func initStream(key: Bytes? = nil, salt: Bytes, personal: Bytes) -> Stream? {
        return Stream(key: key, salt: salt, personal: personal, outputLength: Bytes)
    }
    
    /**
     * blake2b_salt_personal
     */
    public func initStream(key: Bytes?, salt: Bytes, personal: Bytes, outputLength: Int) -> Stream? {
        return Stream(key: key, salt: salt, personal: personal, outputLength: outputLength)
    }
    
    /**
     * blake2b_salt_personal
     */
    public func initStream(salt: Bytes, personal: Bytes, outputLength: Int) -> Stream? {
        return Stream(key: nil, salt: salt, personal: personal, outputLength: outputLength)
    }
}

extension GenericHashBlake2bSaltPersonal.Stream {
    @discardableResult
    public func update(input: Bytes) -> Bool {
        return .SUCCESS == crypto_generichash_blake2b_update(
            &state,
            input, UInt64(input.count)
            ).exitCode
    }
    
    public func final() -> Bytes? {
        let outputLen = outputLength
        var output = Array<UInt8>(count: outputLen)
        guard .SUCCESS == crypto_generichash_blake2b_final(
            &state,
            &output, outputLen
            ).exitCode else { return nil }
        
        return output
    }
}

extension GenericHashBlake2bSaltPersonal: SecretKeyGenerator {
    public var KeyBytes: Int { return Int(crypto_generichash_blake2b_keybytes()) }
    public typealias Key = Bytes
    
    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_generichash_blake2b_keygen
    
}
