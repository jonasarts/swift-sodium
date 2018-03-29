//  Created by Jonas Hauser on 26.05.17.

import Foundation
import Clibsodium

public class AEAD {
    public let AES256GCMKeyBytes = Int(crypto_aead_aes256gcm_keybytes())
    public let AES256GCMSecBytes = Int(crypto_aead_aes256gcm_nsecbytes())
    public let AES256GCMNonceBytes = Int(crypto_aead_aes256gcm_npubbytes())
    public let AES256GCMABytes = Int(crypto_aead_aes256gcm_abytes())

    public typealias Key = Data
    public typealias Nonce = Data
    
    func isAvail() -> Bool {
        return crypto_aead_aes256gcm_is_available() != 0
    }

    public func key() -> Key? {
        var k = Data(count: AES256GCMKeyBytes)
        k.withUnsafeMutableBytes { kPtr in
            randombytes_buf(kPtr, k.count)
        }
        return k
    }
    
    public func nonce() -> Nonce {
        var nonce = Data(count: AES256GCMNonceBytes)
        nonce.withUnsafeMutableBytes { noncePtr in
            randombytes_buf(noncePtr, nonce.count)
        }
        return nonce
    }
    
    public func seal(message: Data, additionalData: Data? = nil, key: Key) -> (authenticatedCipherText: Data, nonce: Nonce)? {
        if !isAvail() {
            return nil
        }
        
        if key.count != AES256GCMKeyBytes {
            return nil
        }
        
        let nonce = self.nonce()
        let authenticatedCipherText = seal(message: message, additionalData: additionalData, nonce: nonce, key: key)
        
        if authenticatedCipherText == nil {
            return nil
        } else {
            return (authenticatedCipherText: authenticatedCipherText!, nonce: nonce)
        }
    }
    
    public func seal(message: Data, additionalData: Data? = nil, nonce: Nonce, key: Key) -> Data? {
        if !isAvail() {
            return nil
        }
        
        if key.count != AES256GCMKeyBytes {
            return nil
        }
        
        if nonce.count != AES256GCMNonceBytes {
            return nil
        }
        
        /*
         crypto_aead_aes256gcm_encrypt(
             unsigned char *c,
             unsigned long long *clen_p,
             const unsigned char *m,
             unsigned long long mlen,
             const unsigned char *ad,
             unsigned long long adlen,
             const unsigned char *nsec,
             const unsigned char *npub,
             const unsigned char *k
         )
         */
        
        var authenticatedCipherText = Data(count: message.count + AES256GCMABytes)
        //var authenticatedCipherTextLength: CUnsignedLongLong = 0

        var result: Int32 = -1
        
        if let additionalData = additionalData {
            result = authenticatedCipherText.withUnsafeMutableBytes { authenticatedCipherTextPtr in
                return message.withUnsafeBytes { messagePtr in
                    return additionalData.withUnsafeBytes { additionalDataPtr in
                        return nonce.withUnsafeBytes { noncePtr in
                            return key.withUnsafeBytes { keyPtr in
                                return crypto_aead_aes256gcm_encrypt(
                                    authenticatedCipherTextPtr,
                                    nil, //&authenticatedCipherTextLength,
                                    messagePtr,
                                    CUnsignedLongLong(message.count),
                                    additionalDataPtr,
                                    CUnsignedLongLong(additionalData.count),
                                    nil,
                                    noncePtr,
                                    keyPtr
                                )
                            }
                        }
                    }
                }
            }
        } else {
            result = authenticatedCipherText.withUnsafeMutableBytes { authenticatedCipherTextPtr in
                return message.withUnsafeBytes { messagePtr in
                    return nonce.withUnsafeBytes { noncePtr in
                        return key.withUnsafeBytes { keyPtr in
                            return crypto_aead_aes256gcm_encrypt(
                                authenticatedCipherTextPtr,
                                nil, //&authenticatedCipherTextLength,
                                messagePtr,
                                CUnsignedLongLong(message.count),
                                nil,
                                CUnsignedLongLong(0),
                                nil,
                                noncePtr,
                                keyPtr
                            )
                        }
                    }
                }
            }
        }
        
        if result != 0 {
            return nil
        }
        
        return authenticatedCipherText
    }
 
    public func open(authenticatedCipherText: Data, additionalData: Data? = nil, nonce: Nonce, key: Key) -> Data? {
        if !isAvail() {
            return nil
        }
        
        if nonce.count != AES256GCMNonceBytes {
            return nil
        }
        
        if key.count != AES256GCMKeyBytes {
            return nil
        }
        
        if authenticatedCipherText.count < AES256GCMABytes {
            return nil
        }

        /*
         crypto_aead_aes256gcm_decrypt(
             unsigned char *m,
             unsigned long long *mlen_p,
             unsigned char *nsec,
             const unsigned char *c,
             unsigned long long clen,
             const unsigned char *ad,
             unsigned long long adlen,
             const unsigned char *npub,
             const unsigned char *k
         )
         */
 
        var message = Data(count: authenticatedCipherText.count - AES256GCMABytes)
        //var messageLength: CUnsignedLongLong = 0
        
        var result: Int32 = -1
        
        if let additionalData = additionalData {
            result = message.withUnsafeMutableBytes { messagePtr in
                return authenticatedCipherText.withUnsafeBytes { authenticatedCipherTextPtr in
                    return additionalData.withUnsafeBytes { additionalDataPtr in
                        return nonce.withUnsafeBytes { noncePtr in
                            return key.withUnsafeBytes { keyPtr in
                                return crypto_aead_aes256gcm_decrypt(
                                    messagePtr,
                                    nil, //&messageLength,
                                    nil,
                                    authenticatedCipherTextPtr,
                                    CUnsignedLongLong(authenticatedCipherText.count),
                                    additionalDataPtr,
                                    CUnsignedLongLong(additionalData.count),
                                    noncePtr,
                                    keyPtr
                                    )
                            }
                        }
                    }
                }
            }
        } else {
            result = message.withUnsafeMutableBytes { messagePtr in
                return authenticatedCipherText.withUnsafeBytes { authenticatedCipherTextPtr in
                    return nonce.withUnsafeBytes { noncePtr in
                        return key.withUnsafeBytes { keyPtr in
                            return crypto_aead_aes256gcm_decrypt(
                                messagePtr,
                                nil, //&messageLength,
                                nil,
                                authenticatedCipherTextPtr,
                                CUnsignedLongLong(authenticatedCipherText.count),
                                nil,
                                CUnsignedLongLong(0),
                                noncePtr,
                                keyPtr
                            )
                        }
                    }
                }
            }
        }
        
        if result != 0 {
            return nil
        }
        
        return message
    }
 
}
