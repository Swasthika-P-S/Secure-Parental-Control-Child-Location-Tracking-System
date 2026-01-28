/**
 * ENHANCED SECURITY INTEGRATION MODULE
 * 
 * This module demonstrates how to integrate key exchange and digital signatures
 * into the existing Parent-Child Location Tracking System.
 * 
 * New Features:
 * 1. Diffie-Hellman key exchange for session encryption
 * 2. RSA digital signatures for critical operations
 * 3. Document signing for legal records
 * 4. Enhanced authentication with signature verification
 */

const crypto = require("crypto");
const { KeyExchange, RSAKeyExchange } = require("./key-exchange");
const { DocumentSigner, RSASignature } = require("./digital-signatures");

/**
 * SESSION MANAGER with Key Exchange
 * 
 * Implements Diffie-Hellman key exchange to establish shared secrets
 * for encrypting sensitive data between client and server.
 */
class SecureSessionManager {
  constructor() {
    // Store active key exchange sessions
    // In production, use Redis or similar for distributed systems
    this.activeSessions = new Map();
  }

  /**
   * Step 1: Server initiates key exchange
   * Returns parameters for client to complete exchange
   */
  initiateKeyExchange(sessionId) {
    const keyExchange = new KeyExchange();
    const params = keyExchange.initializeKeyExchange();
    
    // Store key exchange instance for this session
    this.activeSessions.set(sessionId, {
      keyExchange,
      initiatedAt: Date.now(),
      completed: false
    });

    console.log(`[SESSION] Key exchange initiated for session: ${sessionId}`);

    return {
      sessionId,
      publicKey: params.publicKey,
      prime: params.prime,
      generator: params.generator
    };
  }

  /**
   * Step 2: Complete key exchange with client's public key
   * Returns shared secret for encryption
   */
  completeKeyExchange(sessionId, clientPublicKey) {
    const session = this.activeSessions.get(sessionId);
    
    if (!session) {
      throw new Error("Session not found or expired");
    }

    if (session.completed) {
      throw new Error("Key exchange already completed");
    }

    // Check if session is too old (5 minutes)
    const age = Date.now() - session.initiatedAt;
    if (age > 5 * 60 * 1000) {
      this.activeSessions.delete(sessionId);
      throw new Error("Key exchange session expired");
    }

    // Complete the exchange
    const sharedSecret = session.keyExchange.computeSharedSecret(clientPublicKey);
    session.completed = true;
    session.sharedSecret = sharedSecret;
    session.completedAt = Date.now();

    console.log(`[SESSION] Key exchange completed for session: ${sessionId}`);

    return {
      success: true,
      sessionId,
      message: "Shared secret established"
    };
  }

  /**
   * Get shared secret for a session
   */
  getSharedSecret(sessionId) {
    const session = this.activeSessions.get(sessionId);
    
    if (!session || !session.completed) {
      throw new Error("No valid session found");
    }

    return session.sharedSecret;
  }

  /**
   * Encrypt data using session's shared secret
   */
  encryptWithSession(sessionId, plaintext) {
    const secret = this.getSharedSecret(sessionId);
    
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', secret, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return `${iv.toString('hex')}:${encrypted.toString('hex')}:${tag.toString('hex')}`;
  }

  /**
   * Decrypt data using session's shared secret
   */
  decryptWithSession(sessionId, encryptedData) {
    const secret = this.getSharedSecret(sessionId);
    
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error("Invalid encrypted data format");
    }

    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = Buffer.from(parts[1], 'hex');
    const tag = Buffer.from(parts[2], 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', secret, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Clean up old sessions (run periodically)
   */
  cleanupExpiredSessions() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [sessionId, session] of this.activeSessions.entries()) {
      const age = now - (session.completedAt || session.initiatedAt);
      if (age > maxAge) {
        this.activeSessions.delete(sessionId);
        console.log(`[SESSION] Cleaned up expired session: ${sessionId}`);
      }
    }
  }
}

/**
 * CRITICAL OPERATION SIGNER
 * 
 * Uses RSA digital signatures to sign and verify critical operations
 * like parent-child linking, location updates, etc.
 */
class CriticalOperationSigner {
  constructor() {
    // In production, load keys from secure key storage (KMS, HSM)
    this.serverSigner = new RSASignature();
    this.serverSigner.generateKeyPair();
    
    console.log(`[SIGNER] Server signing keys generated`);
  }

  /**
   * Sign a parent-child link request
   * This creates a non-repudiable record of who linked whom
   */
  signParentChildLink(parentPhone, childPhone, childName) {
    const record = {
      type: "PARENT_CHILD_LINK",
      parentPhone,
      childPhone,
      childName,
      timestamp: new Date().toISOString(),
      nonce: crypto.randomBytes(16).toString('hex')
    };

    const recordString = JSON.stringify(record);
    const signature = this.serverSigner.sign(recordString);

    return {
      record,
      signature,
      publicKey: this.serverSigner.getPublicKey()
    };
  }

  /**
   * Sign a location update
   * Proves location data came from legitimate child device
   */
  signLocationUpdate(childPhone, latitude, longitude, timestamp) {
    const record = {
      type: "LOCATION_UPDATE",
      childPhone,
      latitude,
      longitude,
      timestamp: timestamp || new Date().toISOString(),
      nonce: crypto.randomBytes(16).toString('hex')
    };

    const recordString = JSON.stringify(record);
    const signature = this.serverSigner.sign(recordString);

    return {
      record,
      signature,
      publicKey: this.serverSigner.getPublicKey()
    };
  }

  /**
   * Verify a signed operation
   */
  verifySignedOperation(signedOperation) {
    const { record, signature, publicKey } = signedOperation;
    const recordString = JSON.stringify(record);
    
    return RSASignature.verify(recordString, signature, publicKey);
  }

  /**
   * Get server's public key for verification
   */
  getPublicKey() {
    return this.serverSigner.getPublicKey();
  }
}

/**
 * ENHANCED AUTHENTICATION SERVICE
 * 
 * Combines existing password authentication with digital signatures
 * for stronger non-repudiation
 */
class EnhancedAuthService {
  constructor() {
    this.authSigner = new RSASignature();
    this.authSigner.generateKeyPair();
  }

  /**
   * Generate signed authentication token
   * This is in addition to JWT - provides extra verification layer
   */
  generateSignedAuthToken(userId, username, phone, role) {
    const authData = {
      userId,
      username,
      phone,
      role,
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      nonce: crypto.randomBytes(16).toString('hex')
    };

    const signature = this.authSigner.sign(JSON.stringify(authData));

    return {
      authData,
      signature,
      publicKey: this.authSigner.getPublicKey()
    };
  }

  /**
   * Verify signed authentication token
   */
  verifySignedAuthToken(signedToken) {
    const { authData, signature, publicKey } = signedToken;
    
    // Verify signature
    const isValid = RSASignature.verify(
      JSON.stringify(authData),
      signature,
      publicKey
    );

    if (!isValid) {
      return { valid: false, reason: "Invalid signature" };
    }

    // Check expiration
    const expiresAt = new Date(authData.expiresAt);
    if (expiresAt < new Date()) {
      return { valid: false, reason: "Token expired" };
    }

    return { valid: true, authData };
  }
}

/**
 * AUDIT TRAIL WITH DIGITAL SIGNATURES
 * 
 * Creates tamper-proof audit logs using digital signatures
 */
class SignedAuditLog {
  constructor() {
    this.auditSigner = new RSASignature();
    this.auditSigner.generateKeyPair();
    this.logs = [];
  }

  /**
   * Add a signed audit entry
   */
  addEntry(eventType, userId, details) {
    const entry = {
      eventType,
      userId,
      details,
      timestamp: new Date().toISOString(),
      sequenceNumber: this.logs.length,
      // Hash of previous entry (blockchain-style)
      previousHash: this.logs.length > 0 
        ? this.hashEntry(this.logs[this.logs.length - 1])
        : null
    };

    const entryString = JSON.stringify(entry);
    const signature = this.auditSigner.sign(entryString);

    const signedEntry = {
      entry,
      signature,
      publicKey: this.auditSigner.getPublicKey()
    };

    this.logs.push(signedEntry);
    console.log(`[AUDIT] Entry ${entry.sequenceNumber} added: ${eventType}`);

    return signedEntry;
  }

  /**
   * Verify integrity of entire audit log
   */
  verifyIntegrity() {
    for (let i = 0; i < this.logs.length; i++) {
      const signedEntry = this.logs[i];
      const { entry, signature, publicKey } = signedEntry;

      // Verify signature
      const isValid = RSASignature.verify(
        JSON.stringify(entry),
        signature,
        publicKey
      );

      if (!isValid) {
        console.error(`[AUDIT] Signature verification failed at entry ${i}`);
        return { valid: false, tamperedAt: i };
      }

      // Verify chain (except first entry)
      if (i > 0) {
        const expectedPrevHash = this.hashEntry(this.logs[i - 1]);
        if (entry.previousHash !== expectedPrevHash) {
          console.error(`[AUDIT] Chain broken at entry ${i}`);
          return { valid: false, chainBrokenAt: i };
        }
      }
    }

    console.log(`[AUDIT] All ${this.logs.length} entries verified successfully`);
    return { valid: true, totalEntries: this.logs.length };
  }

  /**
   * Hash an entry for chain verification
   */
  hashEntry(signedEntry) {
    const entryString = JSON.stringify(signedEntry.entry);
    return crypto.createHash('sha256').update(entryString).digest('hex');
  }

  /**
   * Get audit trail
   */
  getAuditTrail() {
    return this.logs;
  }
}

module.exports = {
  SecureSessionManager,
  CriticalOperationSigner,
  EnhancedAuthService,
  SignedAuditLog
};