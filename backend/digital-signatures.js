const crypto = require("crypto");

/**
 * DIGITAL SIGNATURE MODULE
 * 
 * This module implements digital signatures using both RSA and ECDSA algorithms.
 * Digital signatures provide:
 * - Authentication: Verify who created the message
 * - Integrity: Ensure message hasn't been tampered with
 * - Non-repudiation: Signer cannot deny signing
 */

class RSASignature {
  constructor() {
    this.keyPair = null;
  }

  /**
   * Generate RSA key pair for signing (2048-bit)
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

    console.log(`[RSA SIGNATURE] Key pair generated (2048-bit)`);
    return {
      publicKey: this.keyPair.publicKey,
      // Private key stays secure - never share!
    };
  }

  /**
   * Sign data using private key
   * @param {string|Buffer} data - Data to sign
   * @returns {string} - Base64 encoded signature
   */
  sign(data) {
    if (!this.keyPair || !this.keyPair.privateKey) {
      throw new Error("Private key not available");
    }

    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();

    const signature = sign.sign(this.keyPair.privateKey);
    return signature.toString('base64');
  }

  /**
   * Verify signature using public key
   * @param {string|Buffer} data - Original data
   * @param {string} signatureBase64 - Base64 signature
   * @param {string} publicKey - PEM formatted public key
   * @returns {boolean} - True if signature is valid
   */
  static verify(data, signatureBase64, publicKey) {
    const signature = Buffer.from(signatureBase64, 'base64');
    
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();

    const isValid = verify.verify(publicKey, signature);
    return isValid;
  }

  /**
   * Get public key for sharing
   */
  getPublicKey() {
    if (!this.keyPair || !this.keyPair.publicKey) {
      throw new Error("Public key not available");
    }
    return this.keyPair.publicKey;
  }
}

class ECDSASignature {
  constructor() {
    this.keyPair = null;
  }

  /**
   * Generate ECDSA key pair using secp256k1 curve (same as Bitcoin)
   */
  generateKeyPair() {
    this.keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    console.log(`[ECDSA SIGNATURE] Key pair generated (secp256k1 curve)`);
    return {
      publicKey: this.keyPair.publicKey,
    };
  }

  /**
   * Sign data using ECDSA private key
   * @param {string|Buffer} data - Data to sign
   * @returns {string} - Base64 encoded signature
   */
  sign(data) {
    if (!this.keyPair || !this.keyPair.privateKey) {
      throw new Error("Private key not available");
    }

    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();

    const signature = sign.sign(this.keyPair.privateKey);
    return signature.toString('base64');
  }

  /**
   * Verify ECDSA signature
   * @param {string|Buffer} data - Original data
   * @param {string} signatureBase64 - Base64 signature
   * @param {string} publicKey - PEM formatted public key
   * @returns {boolean} - True if signature is valid
   */
  static verify(data, signatureBase64, publicKey) {
    const signature = Buffer.from(signatureBase64, 'base64');
    
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();

    const isValid = verify.verify(publicKey, signature);
    return isValid;
  }

  getPublicKey() {
    if (!this.keyPair) {
      throw new Error("Key pair not generated. Call generateKeyPair() first.");
    }
    return this.keyPair.publicKey;
  }
}

/**
 * HMAC-based Message Authentication (not true digital signature, but useful)
 * This is what JWT uses internally
 */
class HMACAuth {
  /**
   * Create HMAC signature for message
   * @param {string|Buffer} message - Message to authenticate
   * @param {Buffer|string} key - Secret key
   * @returns {string} - Hex HMAC
   */
  static createHMAC(message, key) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(message);
    const signature = hmac.digest('hex');
    return signature;
  }

  /**
   * Verify HMAC signature
   * @param {string|Buffer} message - Original message
   * @param {string} signatureHex - Hex HMAC signature
   * @param {Buffer|string} key - Secret key
   * @returns {boolean} - True if valid
   */
  static verifyHMAC(message, signatureHex, key) {
    const expectedSignature = HMACAuth.createHMAC(message, key);
    
    // Use timing-safe comparison to prevent timing attacks
    try {
      const expected = Buffer.from(expectedSignature, 'hex');
      const provided = Buffer.from(signatureHex, 'hex');
      
      if (expected.length !== provided.length) {
        return false;
      }
      
      const isValid = crypto.timingSafeEqual(expected, provided);
      return isValid;
    } catch (err) {
      return false;
    }
  }
}

/**
 * PRACTICAL IMPLEMENTATION: Sign and verify JSON data
 * This is how you'd use it in your application
 */
class DocumentSigner {
  constructor(algorithm = 'rsa') {
    this.signer = algorithm === 'rsa' ? new RSASignature() : new ECDSASignature();
    this.signer.generateKeyPair();
  }

  /**
   * Sign a JSON document
   * @param {Object} document - Document to sign
   * @returns {Object} - Signed document with signature
   */
  signDocument(document) {
    const documentString = JSON.stringify(document);
    const signature = this.signer.sign(documentString);
    
    return {
      document,
      signature,
      publicKey: this.signer.getPublicKey(),
      algorithm: this.signer instanceof RSASignature ? 'RSA-SHA256' : 'ECDSA-SHA256',
      signedAt: new Date().toISOString()
    };
  }

  /**
   * Verify a signed document
   * @param {Object} signedDoc - Document with signature
   * @returns {boolean} - True if signature is valid
   */
  static verifyDocument(signedDoc) {
    const { document, signature, publicKey, algorithm } = signedDoc;
    const documentString = JSON.stringify(document);
    
    if (algorithm === 'RSA-SHA256') {
      return RSASignature.verify(documentString, signature, publicKey);
    } else if (algorithm === 'ECDSA-SHA256') {
      return ECDSASignature.verify(documentString, signature, publicKey);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }
}

module.exports = {
  RSASignature,
  ECDSASignature,
  HMACAuth,
  DocumentSigner
};