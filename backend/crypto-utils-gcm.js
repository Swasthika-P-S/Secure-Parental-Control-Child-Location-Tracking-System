const crypto = require('crypto');

// Get AES key from security module or environment
let AES_KEY;
try {
  const { AES_KEY: importedKey } = require('./security');
  AES_KEY = importedKey;
} catch (err) {
  // Fallback if security.js not available
  AES_KEY = process.env.AES_KEY || crypto.randomBytes(32).toString('hex');
  console.warn('⚠️ Using fallback AES_KEY. This should only happen in development.');
}

// Ensure key is a Buffer
const getKeyBuffer = () => {
  if (Buffer.isBuffer(AES_KEY)) {
    return AES_KEY;
  }
  // If it's a hex string, convert to buffer
  if (typeof AES_KEY === 'string') {
    return Buffer.from(AES_KEY, 'hex');
  }
  throw new Error('Invalid AES_KEY format');
};

/**
 * Encrypt data using AES-256-GCM
 * @param {string} plaintext - Data to encrypt
 * @returns {string} - Encrypted data in format: iv:authTag:ciphertext (all hex)
 */
function encryptGCM(plaintext) {
  try {
    if (!plaintext) {
      throw new Error('Cannot encrypt empty data');
    }

    const key = getKeyBuffer();
    
    // Validate key length (must be 32 bytes for AES-256)
    if (key.length !== 32) {
      throw new Error(`Invalid key length: ${key.length} bytes (expected 32 bytes for AES-256)`);
    }

    // Generate random IV (12 bytes is recommended for GCM)
    const iv = crypto.randomBytes(12);
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    // Encrypt the data
    let encrypted = cipher.update(String(plaintext), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Get authentication tag
    const authTag = cipher.getAuthTag();
    
    // Return format: iv:authTag:ciphertext (all in hex)
    const result = `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    
    return result;
  } catch (err) {
    console.error('[encryptGCM] Encryption failed:', err.message);
    throw new Error(`Encryption failed: ${err.message}`);
  }
}

/**
 * Decrypt data using AES-256-GCM
 * @param {string} encryptedData - Encrypted data in format: iv:authTag:ciphertext (all hex)
 * @returns {string} - Decrypted plaintext
 */
function decryptGCM(encryptedData) {
  try {
    if (!encryptedData) {
      throw new Error('Cannot decrypt empty data');
    }

    // Split the encrypted data
    const parts = String(encryptedData).split(':');
    
    if (parts.length !== 3) {
      throw new Error(`Invalid encrypted data format. Expected 3 parts (iv:authTag:ciphertext), got ${parts.length}`);
    }

    const [ivHex, authTagHex, encryptedHex] = parts;
    
    // Convert from hex to buffers
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const key = getKeyBuffer();
    
    // Validate key length
    if (key.length !== 32) {
      throw new Error(`Invalid key length: ${key.length} bytes (expected 32 bytes for AES-256)`);
    }
    
    // Validate IV length (should be 12 bytes for GCM)
    if (iv.length !== 12) {
      throw new Error(`Invalid IV length: ${iv.length} bytes (expected 12 bytes)`);
    }
    
    // Validate auth tag length (should be 16 bytes for GCM)
    if (authTag.length !== 16) {
      throw new Error(`Invalid auth tag length: ${authTag.length} bytes (expected 16 bytes)`);
    }
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    
    // Set authentication tag
    decipher.setAuthTag(authTag);
    
    // Decrypt the data
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (err) {
    console.error('[decryptGCM] Decryption failed:', err.message);
    
    // Provide more helpful error messages
    if (err.message.includes('Unsupported state or unable to authenticate data')) {
      throw new Error('Decryption failed: Authentication failed. Data may be corrupted or encrypted with different key.');
    }
    
    throw new Error(`Decryption failed: ${err.message}`);
  }
}

/**
 * Test the encryption/decryption functions
 * Use this to verify your crypto setup is working
 */
function testCrypto() {
  console.log('\n========================================');
  console.log('Testing AES-256-GCM Encryption');
  console.log('========================================\n');
  
  try {
    const testData = 'Hello, World! 123.456';
    console.log('Original data:', testData);
    
    const encrypted = encryptGCM(testData);
    console.log('Encrypted:', encrypted.substring(0, 50) + '...');
    console.log('Encrypted length:', encrypted.length);
    
    const decrypted = decryptGCM(encrypted);
    console.log('Decrypted:', decrypted);
    
    if (testData === decrypted) {
      console.log('\n✅ Encryption/Decryption test PASSED');
    } else {
      console.log('\n❌ Encryption/Decryption test FAILED');
      console.log('Expected:', testData);
      console.log('Got:', decrypted);
    }
    
    // Test with numbers (simulating latitude/longitude)
    console.log('\n--- Testing with coordinates ---');
    const lat = '28.6139';
    const lon = '77.2090';
    
    const encLat = encryptGCM(lat);
    const encLon = encryptGCM(lon);
    
    console.log('Latitude encrypted length:', encLat.length);
    console.log('Longitude encrypted length:', encLon.length);
    
    const decLat = decryptGCM(encLat);
    const decLon = decryptGCM(encLon);
    
    console.log('Decrypted latitude:', decLat);
    console.log('Decrypted longitude:', decLon);
    
    if (lat === decLat && lon === decLon) {
      console.log('✅ Coordinate encryption test PASSED\n');
    } else {
      console.log('❌ Coordinate encryption test FAILED\n');
    }
    
  } catch (err) {
    console.error('\n❌ Test FAILED with error:', err.message);
  }
  
  console.log('========================================\n');
}

// Run test if this file is executed directly
if (require.main === module) {
  testCrypto();
}

module.exports = {
  encryptGCM,
  decryptGCM,
  testCrypto
};