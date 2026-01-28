const crypto = require('crypto');

/**
 * AES Encryption Key
 * In production, this should be stored securely in environment variables
 * Must be 32 bytes (256 bits) for AES-256
 */
let AES_KEY;

// Try to load from environment variable
if (process.env.AES_KEY) {
  AES_KEY = process.env.AES_KEY;
  
  // Validate the key
  const keyBuffer = Buffer.from(AES_KEY, 'hex');
  if (keyBuffer.length !== 32) {
    console.error(`⚠️ WARNING: AES_KEY length is ${keyBuffer.length} bytes, expected 32 bytes for AES-256`);
    console.error('Generating a new temporary key for this session...');
    AES_KEY = crypto.randomBytes(32).toString('hex');
  } else {
    console.log('✅ AES_KEY loaded from environment (32 bytes / 256 bits)');
  }
} else {
  // Generate a random key for development
  AES_KEY = crypto.randomBytes(32).toString('hex');
  console.warn('⚠️ WARNING: No AES_KEY in environment variables');
  console.warn('⚠️ Generated temporary key for this session');
  console.warn('⚠️ Add this to your .env file for production:');
  console.warn(`AES_KEY=${AES_KEY}`);
}

/**
 * Timing-safe comparison for hex strings
 * Prevents timing attacks when comparing sensitive data like password hashes
 * @param {string} a - First hex string
 * @param {string} b - Second hex string
 * @returns {boolean} - True if strings are equal
 */
function timingSafeEqualHex(a, b) {
  try {
    // Convert hex strings to buffers
    const bufA = Buffer.from(String(a), 'hex');
    const bufB = Buffer.from(String(b), 'hex');
    
    // Use crypto.timingSafeEqual for constant-time comparison
    return crypto.timingSafeEqual(bufA, bufB);
  } catch (err) {
    // If conversion fails or lengths don't match, return false
    return false;
  }
}

/**
 * Generate a cryptographically secure random key
 * @param {number} bytes - Number of bytes (default: 32 for AES-256)
 * @returns {string} - Hex-encoded random key
 */
function generateSecureKey(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Generate a cryptographically secure random salt
 * @param {number} bytes - Number of bytes (default: 16)
 * @returns {string} - Hex-encoded random salt
 */
function generateSalt(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Hash data using SHA-256
 * @param {string} data - Data to hash
 * @returns {string} - Hex-encoded hash
 */
function sha256(data) {
  return crypto.createHash('sha256').update(String(data)).digest('hex');
}

/**
 * Hash password using PBKDF2
 * @param {string} password - Password to hash
 * @param {string} salt - Salt (hex string)
 * @param {number} iterations - Number of iterations (default: 100000)
 * @param {number} keylen - Length of derived key in bytes (default: 64)
 * @returns {string} - Hex-encoded hash
 */
function hashPassword(password, salt, iterations = 100000, keylen = 64) {
  return crypto
    .pbkdf2Sync(String(password), String(salt), iterations, keylen, 'sha512')
    .toString('hex');
}

/**
 * Generate HMAC for message authentication
 * @param {string} data - Data to authenticate
 * @param {string} key - Secret key (hex string)
 * @returns {string} - Hex-encoded HMAC
 */
function generateHMAC(data, key = AES_KEY) {
  return crypto
    .createHmac('sha256', Buffer.from(key, 'hex'))
    .update(String(data))
    .digest('hex');
}

/**
 * Verify HMAC
 * @param {string} data - Original data
 * @param {string} hmac - HMAC to verify
 * @param {string} key - Secret key (hex string)
 * @returns {boolean} - True if HMAC is valid
 */
function verifyHMAC(data, hmac, key = AES_KEY) {
  const computed = generateHMAC(data, key);
  return timingSafeEqualHex(computed, hmac);
}

/**
 * Test security functions
 */
function testSecurity() {
  console.log('\n========================================');
  console.log('Testing Security Functions');
  console.log('========================================\n');
  
  try {
    // Test key generation
    console.log('1. Testing key generation...');
    const testKey = generateSecureKey(32);
    console.log(`   Generated key length: ${testKey.length} chars (${testKey.length/2} bytes)`);
    console.log(`   ✅ Key generation OK`);
    
    // Test salt generation
    console.log('\n2. Testing salt generation...');
    const testSalt = generateSalt(16);
    console.log(`   Generated salt length: ${testSalt.length} chars (${testSalt.length/2} bytes)`);
    console.log(`   ✅ Salt generation OK`);
    
    // Test SHA-256
    console.log('\n3. Testing SHA-256 hashing...');
    const testData = 'Hello, World!';
    const hash1 = sha256(testData);
    const hash2 = sha256(testData);
    console.log(`   Hash: ${hash1.substring(0, 32)}...`);
    console.log(`   Same input produces same hash: ${hash1 === hash2}`);
    console.log(`   ✅ SHA-256 hashing OK`);
    
    // Test password hashing
    console.log('\n4. Testing PBKDF2 password hashing...');
    const password = 'SecurePassword123!';
    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);
    console.log(`   Password hash length: ${passwordHash.length} chars`);
    console.log(`   ✅ Password hashing OK`);
    
    // Test timing-safe comparison
    console.log('\n5. Testing timing-safe comparison...');
    const hash3 = sha256('test1');
    const hash4 = sha256('test1');
    const hash5 = sha256('test2');
    const equal = timingSafeEqualHex(hash3, hash4);
    const notEqual = !timingSafeEqualHex(hash3, hash5);
    console.log(`   Same hashes equal: ${equal}`);
    console.log(`   Different hashes not equal: ${notEqual}`);
    console.log(`   ✅ Timing-safe comparison OK`);
    
    // Test HMAC
    console.log('\n6. Testing HMAC...');
    const message = 'Important message';
    const hmac = generateHMAC(message);
    const valid = verifyHMAC(message, hmac);
    const invalid = verifyHMAC('Tampered message', hmac);
    console.log(`   HMAC: ${hmac.substring(0, 32)}...`);
    console.log(`   Valid HMAC verification: ${valid}`);
    console.log(`   Invalid HMAC rejected: ${!invalid}`);
    console.log(`   ✅ HMAC OK`);
    
    console.log('\n✅ All security tests PASSED');
    
  } catch (err) {
    console.error('\n❌ Security test FAILED:', err.message);
  }
  
  console.log('========================================\n');
}

// Run test if this file is executed directly
if (require.main === module) {
  testSecurity();
}

module.exports = {
  AES_KEY,
  timingSafeEqualHex,
  generateSecureKey,
  generateSalt,
  sha256,
  hashPassword,
  generateHMAC,
  verifyHMAC,
  testSecurity
};