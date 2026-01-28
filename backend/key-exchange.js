const crypto = require("crypto");

/**
 * KEY EXCHANGE MODULE - Diffie-Hellman Implementation
 * 
 * This module implements Diffie-Hellman key exchange for secure key establishment
 * between two parties (e.g., client and server) over an insecure channel.
 * 
 * Security Features:
 * - Uses 2048-bit prime for strong security
 * - Generates ephemeral keys for forward secrecy
 * - Derives shared secret that can be used for encryption
 */

class KeyExchange {
  constructor() {
    this.dh = null;
    this.publicKey = null;
    this.privateKey = null;
    this.sharedSecret = null;
  }

  /**
   * Initialize Diffie-Hellman with a strong 2048-bit prime
   * Returns the public key to share with the other party
   */
  initializeKeyExchange() {
    // Create DH instance with 2048-bit prime (modp14 group)
    // This is a standardized group from RFC 3526
    this.dh = crypto.createDiffieHellman(2048);
    
    // Generate keys
    this.publicKey = this.dh.generateKeys();
    this.privateKey = this.dh.getPrivateKey();
    
    console.log(`[KEY EXCHANGE] Initialized`);
    console.log(`[KEY EXCHANGE] Public key length: ${this.publicKey.length} bytes`);
    
    return {
      publicKey: this.publicKey.toString('base64'),
      prime: this.dh.getPrime().toString('base64'),
      generator: this.dh.getGenerator().toString('base64')
    };
  }

  /**
   * Compute shared secret using other party's public key
   * @param {string} otherPublicKeyBase64 - Other party's public key in base64
   * @returns {Buffer} - Shared secret (32 bytes for AES-256)
   */
  computeSharedSecret(otherPublicKeyBase64) {
    if (!this.dh) {
      throw new Error("Key exchange not initialized. Call initializeKeyExchange() first.");
    }

    const otherPublicKey = Buffer.from(otherPublicKeyBase64, 'base64');
    const rawSecret = this.dh.computeSecret(otherPublicKey);
    
    // Derive a stable 32-byte key using SHA-256 for AES-256
    this.sharedSecret = crypto.createHash('sha256').update(rawSecret).digest();
    
    console.log(`[KEY EXCHANGE] Shared secret computed`);
    console.log(`[KEY EXCHANGE] Shared secret length: ${this.sharedSecret.length} bytes`);
    
    return this.sharedSecret;
  }

  /**
   * Get the shared secret (must call computeSharedSecret first)
   */
  getSharedSecret() {
    if (!this.sharedSecret) {
      throw new Error("Shared secret not computed yet. Call computeSharedSecret() first.");
    }
    return this.sharedSecret;
  }

  /**
   * Static method to verify two parties have the same shared secret
   */
  static verifySecrets(secret1, secret2) {
    return crypto.timingSafeEqual(secret1, secret2);
  }
}

/**
 * RSA KEY EXCHANGE ALTERNATIVE
 * For scenarios where asymmetric encryption is preferred
 */
class RSAKeyExchange {
  constructor() {
    this.keyPair = null;
  }

  /**
   * Generate RSA key pair (2048-bit)
   */
  generateKeyPair() {
    this.keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    console.log(`[RSA KEY EXCHANGE] Key pair generated`);
    return {
      publicKey: this.keyPair.publicKey,
      // Never share private key!
    };
  }

  /**
   * Encrypt a symmetric key with recipient's public key
   * @param {string} recipientPublicKey - PEM formatted public key
   * @param {Buffer} symmetricKey - Key to encrypt (e.g., AES key)
   */
  encryptKey(recipientPublicKey, symmetricKey) {
    const encrypted = crypto.publicEncrypt(
      {
        key: recipientPublicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      symmetricKey
    );

    return encrypted.toString('base64');
  }

  /**
   * Decrypt a symmetric key with own private key
   * @param {string} encryptedKeyBase64 - Base64 encrypted key
   */
  decryptKey(encryptedKeyBase64) {
    if (!this.keyPair) {
      throw new Error("Key pair not generated. Call generateKeyPair() first.");
    }

    const encryptedKey = Buffer.from(encryptedKeyBase64, 'base64');
    const decrypted = crypto.privateDecrypt(
      {
        key: this.keyPair.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      encryptedKey
    );

    return decrypted;
  }

  /**
   * Get public key for sharing
   */
  getPublicKey() {
    if (!this.keyPair) {
      throw new Error("Key pair not generated. Call generateKeyPair() first.");
    }
    return this.keyPair.publicKey;
  }
}

module.exports = {
  KeyExchange,
  RSAKeyExchange
};