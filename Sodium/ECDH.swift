//  Created by Jonas Hauser on 26.05.17.

import Foundation
import Clibsodium

public struct ECDH {
    public let DHBytes = Int(crypto_scalarmult_bytes())
    public let DHScalarBytes = Int(crypto_scalarmult_scalarbytes())
}

extension ECDH {
    
    public func publicKey(_ secretKey: Key) -> Key? {
        guard secretKey.count == DHScalarBytes else { return nil }
        
        var publicKey = Bytes(count: DHBytes)
        
        // q = shared secret
        // n = secret key = crypto_scalarmult_SCALARBYTES
        let result = crypto_scalarmult_base(&publicKey, secretKey)
        
        if result != 0 {
            return nil
        }
        
        return publicKey
    }
    
    public func secret(_ secretKey: Key, _ publicKey: Key) -> Key? {
        guard secretKey.count == DHScalarBytes, publicKey.count == DHBytes else { return nil }
        
        var sharedSecret = Bytes(count: DHBytes)
        
        // q = shared secret
        // n = secret key = crypto_scalarmult_SCALARBYTES
        // p = public key
        let result = crypto_scalarmult(&sharedSecret, secretKey, publicKey)
    
        if result != 0 {
            return nil
        }
        
        return sharedSecret
    }
    
}

extension ECDH {
    public typealias Key = Bytes
    public typealias PublicKey = Bytes
    public typealias SecretKey = Bytes
    
    public struct KeyPair {
        public typealias PublicKey = ECDH.PublicKey
        public typealias SecretKey = ECDH.SecretKey
        public let publicKey: PublicKey
        public let secretKey: SecretKey
        
        public init(publicKey: PublicKey, secretKey: SecretKey) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }
}
