#!/usr/bin/env node

/**
 * Test Script for Child Location Tracker - Encryption Verification
 * 
 * This script tests the encryption/decryption functionality
 * Run: node test-encryption.js
 */

const crypto = require('crypto');

console.log('\n' + '='.repeat(70));
console.log('CHILD LOCATION TRACKER - ENCRYPTION VERIFICATION TEST');
console.log('='.repeat(70) + '\n');

// Test 1: Check if required files exist
console.log('TEST 1: Checking required files...');
const fs = require('fs');
const requiredFiles = [
  './security.js',
  './crypto-utils-gcm.js',
  './server.js'
];

let allFilesExist = true;
requiredFiles.forEach(file => {
  if (fs.existsSync(file)) {
    console.log(`  ✅ ${file} exists`);
  } else {
    console.log(`  ❌ ${file} NOT FOUND`);
    allFilesExist = false;
  }
});

if (!allFilesExist) {
  console.log('\n❌ Some required files are missing. Please ensure all files are in place.');
  process.exit(1);
}

console.log('✅ All required files found\n');

// Test 2: Load and test security module
console.log('TEST 2: Testing security.js module...');
try {
  const { AES_KEY, timingSafeEqualHex, sha256 } = require('./security');
  
  // Check AES key
  if (!AES_KEY) {
    throw new Error('AES_KEY is not defined');
  }
  
  const keyBuffer = Buffer.from(AES_KEY, 'hex');
  console.log(`  ✅ AES_KEY loaded (${keyBuffer.length} bytes / ${keyBuffer.length * 8} bits)`);
  
  if (keyBuffer.length !== 32) {
    console.log(`  ⚠️  WARNING: Key is ${keyBuffer.length} bytes, should be 32 bytes for AES-256`);
  }
  
  // Test timing-safe comparison
  const hash1 = sha256('test');
  const hash2 = sha256('test');
  if (timingSafeEqualHex(hash1, hash2)) {
    console.log('  ✅ Timing-safe comparison working');
  } else {
    throw new Error('Timing-safe comparison failed');
  }
  
  console.log('✅ Security module working correctly\n');
} catch (err) {
  console.log(`❌ Security module error: ${err.message}\n`);
  process.exit(1);
}

// Test 3: Load and test encryption module
console.log('TEST 3: Testing crypto-utils-gcm.js module...');
try {
  const { encryptGCM, decryptGCM } = require('./crypto-utils-gcm');
  
  // Test basic encryption/decryption
  const testData = 'Hello, World!';
  const encrypted = encryptGCM(testData);
  const decrypted = decryptGCM(encrypted);
  
  console.log(`  Original: "${testData}"`);
  console.log(`  Encrypted: ${encrypted.substring(0, 40)}...`);
  console.log(`  Decrypted: "${decrypted}"`);
  
  if (testData === decrypted) {
    console.log('  ✅ Basic encryption/decryption working');
  } else {
    throw new Error('Decryption did not return original data');
  }
  
  // Test with coordinates (simulating location data)
  console.log('\n  Testing with coordinate data:');
  const latitude = '28.6139';
  const longitude = '77.2090';
  
  const encLat = encryptGCM(latitude);
  const encLon = encryptGCM(longitude);
  
  console.log(`  Original latitude: ${latitude}`);
  console.log(`  Encrypted latitude: ${encLat.substring(0, 40)}... (${encLat.length} chars)`);
  
  console.log(`  Original longitude: ${longitude}`);
  console.log(`  Encrypted longitude: ${encLon.substring(0, 40)}... (${encLon.length} chars)`);
  
  const decLat = decryptGCM(encLat);
  const decLon = decryptGCM(encLon);
  
  console.log(`  Decrypted latitude: ${decLat}`);
  console.log(`  Decrypted longitude: ${decLon}`);
  
  if (latitude === decLat && longitude === decLon) {
    console.log('  ✅ Coordinate encryption/decryption working');
  } else {
    throw new Error('Coordinate decryption failed');
  }
  
  // Test format validation
  const parts = encrypted.split(':');
  if (parts.length === 3) {
    const [iv, authTag, ciphertext] = parts;
    console.log(`\n  Format validation:`);
    console.log(`    IV length: ${iv.length / 2} bytes (${iv.length} hex chars)`);
    console.log(`    Auth tag length: ${authTag.length / 2} bytes (${authTag.length} hex chars)`);
    console.log(`    Ciphertext length: ${ciphertext.length / 2} bytes (${ciphertext.length} hex chars)`);
    
    if (iv.length === 24 && authTag.length === 32) {
      console.log('  ✅ Format is correct (iv:authTag:ciphertext)');
    } else {
      console.log('  ⚠️  Format may have issues');
    }
  }
  
  console.log('\n✅ Crypto module working correctly\n');
} catch (err) {
  console.log(`❌ Crypto module error: ${err.message}\n`);
  console.error(err.stack);
  process.exit(1);
}

// Test 4: Check server.js has encrypt/decrypt functions
console.log('TEST 4: Checking server.js for encryption functions...');
try {
  const serverContent = fs.readFileSync('./server.js', 'utf8');
  
  const hasEncrypt = serverContent.includes('const encrypt =') || 
                     serverContent.includes('function encrypt(');
  const hasDecrypt = serverContent.includes('const decrypt =') || 
                     serverContent.includes('function decrypt(');
  const usesEncrypt = serverContent.includes('encrypt(');
  const usesDecrypt = serverContent.includes('decrypt(');
  
  console.log(`  Has encrypt function: ${hasEncrypt ? '✅' : '❌'}`);
  console.log(`  Has decrypt function: ${hasDecrypt ? '✅' : '❌'}`);
  console.log(`  Uses encrypt: ${usesEncrypt ? '✅' : '❌'}`);
  console.log(`  Uses decrypt: ${usesDecrypt ? '✅' : '❌'}`);
  
  if (!hasEncrypt) {
    console.log('\n  ⚠️  WARNING: encrypt() function not found in server.js');
    console.log('  This will cause "encrypt is not defined" errors');
    console.log('  Solution: Add the encrypt function wrapper or use the fixed server.js');
  }
  
  if (!hasDecrypt) {
    console.log('\n  ⚠️  WARNING: decrypt() function not found in server.js');
  }
  
  if (hasEncrypt && hasDecrypt) {
    console.log('\n✅ Server.js has required encryption functions\n');
  } else {
    console.log('\n❌ Server.js is missing encryption functions\n');
    console.log('ACTION REQUIRED:');
    console.log('1. Add the encrypt() function to your server.js, OR');
    console.log('2. Replace server.js with the fixed version (server-fixed.js)\n');
  }
} catch (err) {
  console.log(`❌ Error checking server.js: ${err.message}\n`);
}

// Test 5: Environment configuration check
console.log('TEST 5: Checking environment configuration...');
require('dotenv').config();

const requiredEnvVars = [
  'MONGO_URI',
  'JWT_SECRET',
  'AES_KEY'
];

const optionalEnvVars = [
  'ENABLE_SMS',
  'TWILIO_ACCOUNT_SID',
  'TWILIO_AUTH_TOKEN',
  'TWILIO_PHONE_NUMBER'
];

console.log('  Required variables:');
requiredEnvVars.forEach(varName => {
  if (process.env[varName]) {
    const value = varName.includes('KEY') || varName.includes('SECRET') 
      ? '***' + process.env[varName].slice(-4) 
      : process.env[varName];
    console.log(`    ✅ ${varName}: ${value}`);
  } else {
    console.log(`    ❌ ${varName}: NOT SET`);
  }
});

console.log('\n  Optional variables (for SMS):');
optionalEnvVars.forEach(varName => {
  if (process.env[varName]) {
    const value = varName.includes('TOKEN') || varName.includes('SID') 
      ? '***' + process.env[varName].slice(-4) 
      : process.env[varName];
    console.log(`    ✅ ${varName}: ${value}`);
  } else {
    console.log(`    ⚪ ${varName}: Not set`);
  }
});

// Test 6: MongoDB connection (if possible)
console.log('\n\nTEST 6: Testing MongoDB connection...');
const mongoose = require('mongoose');

if (process.env.MONGO_URI) {
  mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000
  })
  .then(() => {
    console.log('  ✅ MongoDB connection successful');
    
    // Check if ChildLocation model exists
    try {
      const ChildLocation = require('./models/ChildLocation');
      console.log('  ✅ ChildLocation model loaded');
      
      // Check schema
      const schema = ChildLocation.schema;
      const latitudeType = schema.path('latitude')?.instance;
      const longitudeType = schema.path('longitude')?.instance;
      
      console.log(`  Latitude field type: ${latitudeType || 'unknown'}`);
      console.log(`  Longitude field type: ${longitudeType || 'unknown'}`);
      
      if (latitudeType === 'String' && longitudeType === 'String') {
        console.log('  ✅ Schema is correct (String types for encrypted data)');
      } else {
        console.log('  ⚠️  WARNING: Schema may need String type for encrypted fields');
      }
    } catch (err) {
      console.log(`  ⚪ Could not verify model: ${err.message}`);
    }
    
    mongoose.connection.close();
    
    console.log('\n' + '='.repeat(70));
    console.log('SUMMARY');
    console.log('='.repeat(70));
    console.log('✅ Encryption system is working correctly!');
    console.log('\nNext steps:');
    console.log('1. Start your server: node server.js');
    console.log('2. Test location update endpoint');
    console.log('3. Test location tracking endpoint');
    console.log('\nIf you encounter "encrypt is not defined" error:');
    console.log('- Replace server.js with server-fixed.js');
    console.log('='.repeat(70) + '\n');
  })
  .catch(err => {
    console.log(`  ❌ MongoDB connection failed: ${err.message}`);
    console.log('  Make sure MongoDB is running and MONGO_URI is correct\n');
    
    console.log('\n' + '='.repeat(70));
    console.log('SUMMARY');
    console.log('='.repeat(70));
    console.log('⚠️  Encryption modules are working, but MongoDB connection failed');
    console.log('\nFix MongoDB connection, then:');
    console.log('1. Start MongoDB service');
    console.log('2. Verify MONGO_URI in .env');
    console.log('3. Start your server: node server.js');
    console.log('='.repeat(70) + '\n');
  });
} else {
  console.log('  ⚠️  MONGO_URI not set, skipping connection test\n');
  
  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY');
  console.log('='.repeat(70));
  console.log('⚠️  Encryption modules are working, but configuration incomplete');
  console.log('\nComplete these steps:');
  console.log('1. Set MONGO_URI in .env');
  console.log('2. Ensure encrypt() function exists in server.js');
  console.log('3. Start your server: node server.js');
  console.log('='.repeat(70) + '\n');
}