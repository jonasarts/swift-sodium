//
//  GenericHashBlake2b.swift
//  Sodium
//
//  Created by Jonas Hauser on 26.05.17.
//  Updated by Jonas Hauser on 17.02.19.
//  Copyright © 2019 Frank Denis. All rights reserved.
//

import Foundation
import Clibsodium

public struct GenericHashBlake2b {
    public let BytesMin = Int(crypto_generichash_blake2b_bytes_min())
    public let BytesMax = Int(crypto_generichash_blake2b_bytes_max())
    public let Bytes = Int(crypto_generichash_blake2b_bytes())
    public let KeyBytesMin = Int(crypto_generichash_blake2b_keybytes_min())
    public let KeyBytesMax = Int(crypto_generichash_blake2b_keybytes_max())
    //public let KeyBytes = Int(crypto_generichash_blake2b_keybytes())
    //public let StateBytes = Int(crypto_generichash_blake2b_statebytes())
}

extension GenericHashBlake2b {
    public class Stream {
        private var state: crypto_generichash_blake2b_state
        public var outputLength: Int = 0
        
        init?(key: Bytes?, outputLength: Int) {
            state = crypto_generichash_blake2b_state()
            
            guard .SUCCESS == crypto_generichash_blake2b_init(
                &state,
                key, key?.count ?? 0,
                outputLength
                ).exitCode else { return nil }
            
            self.outputLength = outputLength
        }
    }
}

extension GenericHashBlake2b {
    /**
     * blake2b
     */
    public func hash(message: Bytes, key: Bytes? = nil) -> Bytes? {
        return hash(message: message, key: key, outputLength: Bytes)
    }
    
    /**
     * blake2b
     */
    public func hash(message: Bytes, key: Bytes?, outputLength: Int) -> Bytes? {
        var output = Array<UInt8>(count: outputLength)
        
        guard .SUCCESS == crypto_generichash_blake2b(
            &output, outputLength,
            message, UInt64(message.count),
            key, key?.count ?? 0
            ).exitCode else { return nil }
        
        return output
    }
    
    /**
     * blake2b
     */
    public func hash(message: Bytes, outputLength: Int) -> Bytes? {
        return hash(message: message, key: nil, outputLength: outputLength)
    }
}

extension GenericHashBlake2b {
    /**
     * blake2b
     */
    public func initStream(key: Bytes? = nil) -> Stream? {
        return Stream(key: key, outputLength: Bytes)
    }
    
    /**
     * blake2b
     */
    public func initStream(key: Bytes?, outputLength: Int) -> Stream? {
        return Stream(key: key, outputLength: outputLength)
    }
    
    /**
     * blake2b
     */
    public func initStream(outputLength: Int) -> Stream? {
        return Stream(key: nil, outputLength: outputLength)
    }
}

extension GenericHashBlake2b.Stream {
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

extension GenericHashBlake2b: SecretKeyGenerator {
    public var KeyBytes: Int { return Int(crypto_generichash_blake2b_keybytes()) }
    public typealias Key = Bytes
    
    public static var keygen: (UnsafeMutablePointer<UInt8>) -> Void = crypto_generichash_blake2b_keygen
    
}
