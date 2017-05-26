//
//  GenericHashBlake2b.swift
//  Sodium
//
//  Created by Jonas Hauser on 26.05.17.
//  Copyright © 2017 Jonas Hauser. All rights reserved.
//

import Foundation
import libsodium

public class GenericHashBlake2b {
    
    public let BytesMin = Int(crypto_generichash_blake2b_bytes_min())
    public let BytesMax = Int(crypto_generichash_blake2b_bytes_max())
    public let Bytes = Int(crypto_generichash_blake2b_bytes())
    public let KeyBytesMin = Int(crypto_generichash_blake2b_keybytes_min())
    public let KeyBytesMax = Int(crypto_generichash_blake2b_keybytes_max())
    public let KeyBytes = Int(crypto_generichash_blake2b_keybytes())
    public let SaltBytes = Int(crypto_generichash_blake2b_saltbytes())
    public let PersonalBytes = Int(crypto_generichash_blake2b_personalbytes())
    //public let StateBytes = Int(crypto_generichash_blake2b_statebytes())

    public typealias Key = Data
    
    /**
     * blake2b
     */
    public func hash(message: Data, key: Data? = nil) -> Data? {
        return hash(message: message, key: key, outputLength: Bytes)
    }
    
    /**
     * blake2b
     */
    public func hash(message: Data, key: Data?, outputLength: Int) -> Data? {
    
        /*
         int crypto_generichash_blake2b(
            unsigned char *out,
            size_t outlen,
            const unsigned char *in,
            unsigned long long inlen,
            const unsigned char *key,
            size_t keylen
         );
         */
        
        var output = Data(count: outputLength)
        var result: Int32 = -1
        
        if let key = key {
            result = output.withUnsafeMutableBytes { outputPtr in
                return message.withUnsafeBytes { messagePtr in
                    return key.withUnsafeBytes { keyPtr in
                        return crypto_generichash_blake2b(
                            outputPtr,
                            output.count,
                            messagePtr,
                            CUnsignedLongLong(message.count),
                            keyPtr,
                            key.count)
                    }
                }
            }
        } else {
            result = output.withUnsafeMutableBytes { outputPtr in
                return message.withUnsafeBytes { messagePtr in
                    return crypto_generichash_blake2b(
                        outputPtr,
                        output.count,
                        messagePtr,
                        CUnsignedLongLong(message.count),
                        nil,
                        0)
                }
            }
        }
        
        if result != 0 {
            return nil
        }
        
        return output
    }
    
    /**
     * blake2b
     */
    public func hash(message: Data, outputLength: Int) -> Data? {
        return hash(message: message, key: nil, outputLength: outputLength)
    }
    
    /**
     * blake2b_salt_personal
     */
    public func hash(message: Data, key: Data? = nil, salt: Data, personal: Data) -> Data? {
        return hash(message: message, key: key, salt: salt, personal: personal, outputLength: Bytes)
    }
    
    /**
     * blake2b_salt_personal
     */
    public func hash(message: Data, key: Data?, salt: Data, personal: Data, outputLength: Int) -> Data? {
    
        /*
         int crypto_generichash_blake2b_salt_personal(
            unsigned char *out,
            size_t outlen,
            const unsigned char *in,
            unsigned long long inlen,
            const unsigned char *key,
            size_t keylen,
            const unsigned char *salt,
            const unsigned char *personal
         );
         */
        
        var output = Data(count: outputLength)
        var result: Int32 = -1
        
        if let key = key {
            result = output.withUnsafeMutableBytes { outputPtr in
                return message.withUnsafeBytes { messagePtr in
                    return key.withUnsafeBytes { keyPtr in
                        return salt.withUnsafeBytes { saltPtr in
                            return personal.withUnsafeBytes { personalPtr in
                                return crypto_generichash_blake2b_salt_personal(
                                    outputPtr,
                                    output.count,
                                    messagePtr,
                                    CUnsignedLongLong(message.count),
                                    keyPtr,
                                    key.count,
                                    saltPtr,
                                    personalPtr)
                            }
                        }
                    }
                }
            }
        } else {
            result = output.withUnsafeMutableBytes { outputPtr in
                return message.withUnsafeBytes { messagePtr in
                    return salt.withUnsafeBytes { saltPtr in
                        return personal.withUnsafeBytes { personalPtr in
                            return crypto_generichash_blake2b_salt_personal(
                                outputPtr,
                                output.count,
                                messagePtr,
                                CUnsignedLongLong(message.count),
                                nil,
                                0,
                                saltPtr,
                                personalPtr)
                        }
                    }
                }
            }
        }
        
        if result != 0 {
            return nil
        }
        
        return output
    }
    
    /**
     * blake2b_salt_personal
     */
    public func hash(message: Data, salt: Data, personal: Data, outputLength: Int) -> Data? {
        return hash(message: message, key: nil, salt: salt, personal: personal, outputLength: outputLength)
    }
    
    /**
     * blake2b
     */
    public func initStream(key: Data? = nil) -> Stream? {
        return Stream(key: key, salt: nil, personal: nil, outputLength: Bytes)
    }
    
    /**
     * blake2b
     */
    public func initStream(key: Data?, outputLength: Int) -> Stream? {
        return Stream(key: key, salt: nil, personal: nil, outputLength: outputLength)
    }
    
    /**
     * blake2b
     */
    public func initStream(outputLength: Int) -> Stream? {
        return Stream(key: nil, salt: nil, personal: nil, outputLength: outputLength)
    }
    
    /**
     * blake2b_salt_personal
     */
    public func initStream(key: Data? = nil, salt: Data, personal: Data) -> Stream? {
        return Stream(key: key, salt: salt, personal: personal, outputLength: Bytes)
    }
    
    /**
     * blake2b_salt_personal
     */
    public func initStream(key: Data?, salt: Data, personal: Data, outputLength: Int) -> Stream? {
        return Stream(key: key, salt: salt, personal: personal, outputLength: outputLength)
    }
    
    /**
     * blake2b_salt_personal
     */
    public func initStream(salt: Data, personal: Data, outputLength: Int) -> Stream? {
        return Stream(key: nil, salt: salt, personal: personal, outputLength: outputLength)
    }
    
    /*
     int crypto_generichash_blake2b_init(
     crypto_generichash_blake2b_state *state,
     const unsigned char *key,
     const size_t keylen,
     const size_t outlen
     );
     */
    /*
     int crypto_generichash_blake2b_init_salt_personal(
     crypto_generichash_blake2b_state *state,
     const unsigned char *key,
     const size_t keylen,
     const size_t outlen,
     const unsigned char *salt,
     const unsigned char *personal
     );
     */
    /*
     int crypto_generichash_blake2b_update(
     crypto_generichash_blake2b_state *state,
     const unsigned char *in,
     unsigned long long inlen
     );
     */
    /*
     int crypto_generichash_blake2b_final(
     crypto_generichash_blake2b_state *state,
     unsigned char *out,
     const size_t outlen
     );
     */
    public class Stream {
        public var outputLength: Int = 0
        private var state: UnsafeMutablePointer<crypto_generichash_blake2b_state>?
        
        init?(key: Data?, salt: Data?, personal: Data?, outputLength: Int) {
            state = UnsafeMutablePointer<crypto_generichash_blake2b_state>.allocate(capacity: 1)
            guard let state = state else {
                return nil
            }
            
            var result: Int32 = -1
            
            if let key = key {
                if let salt = salt, let personal = personal {
                    result = key.withUnsafeBytes { keyPtr in
                        return salt.withUnsafeBytes { saltPtr in
                            return personal.withUnsafeBytes { personalPtr in
                                crypto_generichash_blake2b_init_salt_personal(state, keyPtr, key.count, outputLength, saltPtr, personalPtr)
                            }
                        }
                    }
                } else {
                    result = key.withUnsafeBytes { keyPtr in
                        crypto_generichash_blake2b_init(state, keyPtr, key.count, outputLength)
                    }
                }
            } else {
                if let salt = salt, let personal = personal {
                    result = salt.withUnsafeBytes { saltPtr in
                        return personal.withUnsafeBytes { personalPtr in
                            crypto_generichash_blake2b_init_salt_personal(state, nil, 0, outputLength, saltPtr, personalPtr)
                        }
                    }
                } else {
                    result = crypto_generichash_blake2b_init(state, nil, 0, outputLength)
                }
            }
            
            if result != 0 {
                return nil
            }
            
            self.outputLength = outputLength;
        }
        
        deinit {
            state?.deallocate(capacity: 1)
        }
        
        /**
         Updates the hash stream with incoming data to contribute to the computed fingerprint.
         
         - Parameter input: The incoming stream data.
         
         - Returns: `true` if the data was consumed successfully.
         */
        public func update(input: Data) -> Bool {
            return input.withUnsafeBytes { inputPtr in
                return crypto_generichash_blake2b_update(state!, inputPtr, CUnsignedLongLong(input.count)) == 0
            }
        }
        
        /**
         Signals that the incoming stream of data is complete and triggers computation of the resulting fingerprint.
         
         - Returns: The computed fingerprint.
         */
        public func final() -> Data? {
            var output = Data(count: outputLength)
            let result = output.withUnsafeMutableBytes { outputPtr in
                crypto_generichash_blake2b_final(state!, outputPtr, output.count)
            }
            
            if result != 0 {
                return nil
            }
            
            return output
        }
    }

    /*
     void crypto_generichash_blake2b_keygen(unsigned char k[crypto_generichash_blake2b_KEYBYTES]);
     */
    public func key() -> Key? {
        var k = Data(count: KeyBytes)
        k.withUnsafeMutableBytes { kPtr in
            crypto_generichash_blake2b_keygen(kPtr)
        }
        return k
    }
}
