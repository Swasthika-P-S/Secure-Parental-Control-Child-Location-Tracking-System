require("dotenv").config({ path: __dirname + '/.env' });
const fs = require("fs");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");
const twilio = require("twilio");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");

/* ===================== MODELS ===================== */
const User = require("./models/User");
const Otp = require("./models/Otp");
const ParentChild = require("./models/ParentChild");
const ChildLocation = require("./models/ChildLocation");

/* ===================== SECURITY MODULES ===================== */
const { AES_KEY, timingSafeEqualHex } = require("./security");
const { encryptGCM, decryptGCM } = require("./crypto-utils-gcm");
const { RSASignature, ECDSASignature, HMACAuth, DocumentSigner } = require("./digital-signatures");
const { KeyExchange, RSAKeyExchange } = require("./key-exchange");

/* ===================== ENCRYPTION WRAPPER FUNCTIONS ===================== */
/**
 * Encrypt data using AES-GCM
 * @param {string} data - Data to encrypt
 * @returns {string} - Encrypted data with IV and auth tag
 */
const encrypt = (data) => {
  try {
    return encryptGCM(String(data));
  } catch (err) {
    console.error("Encryption error:", err);
    throw new Error("Encryption failed");
  }
};

/**
 * Decrypt data using AES-GCM
 * @param {string} encryptedData - Encrypted data with IV and auth tag
 * @returns {string} - Decrypted plaintext
 */
const decrypt = (encryptedData) => {
  try {
    return decryptGCM(String(encryptedData));
  } catch (err) {
    console.error("Decryption error:", err);
    throw new Error("Decryption failed");
  }
};

/* ===================== SIGNER INITIALIZATION (singleton) ===================== */
let serverSigner = null;
const RSA_PRIVATE_KEY_ENV = process.env.RSA_PRIVATE_KEY || null;
const RSA_PUBLIC_KEY_ENV = process.env.RSA_PUBLIC_KEY || null;
const RSA_PRIVATE_KEY_PATH = process.env.RSA_PRIVATE_KEY_PATH || null;
const RSA_PUBLIC_KEY_PATH = process.env.RSA_PUBLIC_KEY_PATH || null;

if (RSA_PRIVATE_KEY_ENV && RSA_PUBLIC_KEY_ENV) {
  serverSigner = new RSASignature();
  serverSigner.keyPair = { privateKey: RSA_PRIVATE_KEY_ENV, publicKey: RSA_PUBLIC_KEY_ENV };
  console.log("[signer] RSA keys loaded from environment variables");
} else if (RSA_PRIVATE_KEY_PATH && RSA_PUBLIC_KEY_PATH && fs.existsSync(RSA_PRIVATE_KEY_PATH) && fs.existsSync(RSA_PUBLIC_KEY_PATH)) {
  serverSigner = new RSASignature();
  serverSigner.keyPair = { privateKey: fs.readFileSync(RSA_PRIVATE_KEY_PATH, 'utf8'), publicKey: fs.readFileSync(RSA_PUBLIC_KEY_PATH, 'utf8') };
  console.log("[signer] RSA keys loaded from files");
} else if (process.env.NODE_ENV !== 'production') {
  serverSigner = new RSASignature();
  serverSigner.generateKeyPair();
  console.log("[signer] Generated ephemeral RSA key pair for development");
} else {
  console.warn("[signer] WARNING: No RSA keys configured. Signing will be disabled in production.");
  serverSigner = null;
}

/* ===================== APP START ===================== */
const app = express();

/* ===================== CONFIGURATION ===================== */
const CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex"),
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "7d",
  OTP_EXPIRY: parseInt(process.env.OTP_EXPIRY_MS || String(5 * 60 * 1000), 10),
  OTP_LENGTH: parseInt(process.env.OTP_LENGTH || "6", 10),
  SALT_BYTES: parseInt(process.env.SALT_BYTES || "16", 10),
  PBKDF2_ITERATIONS: parseInt(process.env.PBKDF2_ITERATIONS || "100000", 10),
  PORT: parseInt(process.env.PORT || "5001", 10),
  ENABLE_SMS: process.env.ENABLE_SMS === "true"
};
CONFIG.AES_KEY = AES_KEY; // backward compatibility

if (!process.env.JWT_SECRET) console.warn("⚠️  WARNING: Using random JWT_SECRET. Sessions will reset on restart!");
if (!process.env.AES_KEY) console.warn("⚠️  WARNING: AES_KEY not set. Using derived fallback key (dev only).");

/* ===================== MIDDLEWARE ===================== */
app.use(helmet());
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000','http://localhost:5173','http://localhost:5500'];
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) return callback(null, true);
    callback(null, true);
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit:'10kb', verify:(req,res,buf)=>{ try{ JSON.parse(buf);}catch(e){ const err = new Error('Invalid JSON format'); err.type='entity.parse.failed'; throw err; }}}));
app.use(express.urlencoded({ extended:true, limit:'10kb' }));

if (process.env.NODE_ENV !== 'production') {
  app.use((req,res,next)=>{ console.log(`${req.method} ${req.path}`, req.body || {}); next(); });
}

const generalLimiter = rateLimit({ windowMs:15*60*1000, max:100, message:{success:false,error:"Too many requests"}, standardHeaders:true, legacyHeaders:false });
app.use(generalLimiter);
const otpLimiter = rateLimit({ windowMs:5*60*1000, max:5, message:{success:false,error:"Too many OTP requests"} });
const authLimiter = rateLimit({ windowMs:15*60*1000, max:10, message:{success:false,error:"Too many auth attempts"} });

/* ===================== DATABASE ===================== */
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Error:", err);
    process.exit(1);
  });

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} received, closing server gracefully...`);
  try {
    await mongoose.connection.close();
    console.log("Database connection closed");
    process.exit(0);
  } catch (err) {
    console.error("Error during shutdown:", err);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

/* ===================== SMS SERVICE (IMPROVED) ===================== */
let twilioClient = null;

if (CONFIG.ENABLE_SMS) {
  try {
    twilioClient = twilio(
      process.env.TWILIO_ACCOUNT_SID,
      process.env.TWILIO_AUTH_TOKEN
    );
    console.log("✅ Twilio initialized");
  } catch (err) {
    console.error("❌ Twilio initialization failed:", err.message);
  }
}

const sendSMS = async (to, body) => {
  if (!CONFIG.ENABLE_SMS) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`📱 [SMS DISABLED] OTP for ${to}:`);
    console.log(`Message: ${body}`);
    console.log('='.repeat(60) + '\n');
    if (process.env.NODE_ENV === 'development') {
      return { success: true, message: 'Development mode - check console for OTP' };
    }
    throw new Error('SMS service is currently disabled. Please contact support.');
  }
  
  if (!twilioClient) {
    console.error('❌ Twilio client not initialized');
    throw new Error('SMS service is not available. Please try again later.');
  }
  
  try {
    const message = await twilioClient.messages.create({
      body,
      from: process.env.TWILIO_PHONE_NUMBER,
      to
    });
    console.log(`✅ SMS sent to ${to}, SID: ${message.sid}`);
    return { success: true, sid: message.sid };
  } catch (err) {
    console.error("❌ SMS error:", {
      message: err.message,
      code: err.code,
      status: err.status,
      moreInfo: err.moreInfo
    });
    
    let userMessage = 'Failed to send SMS. Please try again.';
    if (err.code === 21211) userMessage = 'Invalid phone number format. Please check and try again.';
    else if (err.code === 21408) userMessage = 'This phone number is not verified. Please verify it in your Twilio account.';
    else if (err.code === 21610) userMessage = 'Unable to send SMS to this number. It may have opted out.';
    else if (err.code === 20003) userMessage = 'SMS service authentication failed. Please contact support.';
    else if (err.code === 21606) userMessage = 'SMS service configuration error. Please contact support.';
    
    throw new Error(userMessage);
  }
};

/* ===================== SECURITY UTILITIES ===================== */

// Access Control Matrix
const ACM = {
  Parent: {
    ChildLocation: ["read"],
    ChildRegistration: ["create"],
    ParentChild: ["read", "delete"]
  },
  Child: {
    ChildLocation: ["write", "read"]
  },
  Admin: {
    ChildLocation: ["read", "write", "delete"],
    User: ["read", "delete"]
  }
};

const checkAccess = (role, resource, action) => {
  return ACM[role]?.[resource]?.includes(action) || false;
};

// Password hashing
const hashPassword = (password, salt) => {
  return crypto
    .pbkdf2Sync(String(password), String(salt), CONFIG.PBKDF2_ITERATIONS, 64, "sha512")
    .toString("hex");
};

// OTP generation and hashing
const generateOTP = () => {
  return Math.floor(
    Math.pow(10, CONFIG.OTP_LENGTH - 1) + 
    Math.random() * (Math.pow(10, CONFIG.OTP_LENGTH) - Math.pow(10, CONFIG.OTP_LENGTH - 1))
  ).toString();
};

const hashOTP = (otp) => {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
};

/* ===================== JWT helpers & middleware ===================== */
const generateToken = (payload) => {
  return jwt.sign(payload, CONFIG.JWT_SECRET, {
    expiresIn: CONFIG.JWT_EXPIRES_IN
  });
};

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: "No token provided" 
    });
  }
  
  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ 
      success: false,
      error: "Invalid or expired token" 
    });
  }
};

const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false,
        error: "Insufficient permissions" 
      });
    }
    next();
  };
};

/* ===================== VALIDATION ===================== */

const validatePhone = (phone) => {
  const phoneRegex = /^\+?[1-9]\d{1,14}$/; // E.164
  return phoneRegex.test(String(phone));
};

const validatePassword = (password) => {
  if (!password || password.length < 8) {
    return { valid: false, error: "Password must be at least 8 characters" };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: "Password must contain uppercase letter" };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: "Password must contain lowercase letter" };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, error: "Password must contain a number" };
  }
  return { valid: true };
};

const validateUsername = (username) => {
  if (!username || username.length < 3) {
    return { valid: false, error: "Username must be at least 3 characters" };
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return { valid: false, error: "Username can only contain letters, numbers, and underscores" };
  }
  return { valid: true };
};

const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return input.trim();
  }
  return input;
};

/* ===================== ERROR HANDLING / UTILITIES ===================== */

class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/* ===================== OTP MANAGEMENT ===================== */

const createOTP = async (phone, type, additionalData = {}) => {
  const otp = generateOTP();
  const otpHash = hashOTP(otp);
  
  console.log(`[CREATE OTP] Creating OTP for phone: ${phone}, type: ${type}`);
  
  // Delete any existing OTPs for this phone and type
  await Otp.deleteMany({ phone, type });
  
  // Create new OTP record
  const otpRecord = await Otp.create({
    phone,
    otpHash,
    type,
    ...additionalData,
    expiresAt: new Date(Date.now() + CONFIG.OTP_EXPIRY)
  });
  
  console.log(`[CREATE OTP] ✓ OTP created (dev log):`, { phone: otpRecord.phone, type: otpRecord.type, otp: otp, expiresAt: otpRecord.expiresAt });
  
  try {
    await sendSMS(phone, `Your verification code is: ${otp}. Valid for ${Math.floor(CONFIG.OTP_EXPIRY / 1000)} seconds.`);
    console.log(`[CREATE OTP] ✅ SMS sent successfully`);
  } catch (err) {
    console.error(`[CREATE OTP] ❌ Failed to send SMS:`, err.message);
    await Otp.deleteOne({ _id: otpRecord._id });
    throw new AppError(`Unable to send OTP: ${err.message}`, 503);
  }
  
  return otp;
};

const verifyOTP = async (phone, otp, type = null) => {
  const query = { phone };
  if (type) query.type = type;
  
  console.log(`[VERIFY OTP] Query:`, query);
  console.log(`[VERIFY OTP] Input OTP: ${otp}`);
  
  const record = await Otp.findOne(query).sort({ createdAt: -1 });
  if (!record) {
    console.log(`[VERIFY OTP] ❌ No OTP found for phone: ${phone}, type: ${type}`);
    throw new AppError("OTP expired or not found", 400);
  }
  
  console.log(`[VERIFY OTP] Found OTP record:`, {
    phone: record.phone,
    type: record.type,
    expiresAt: record.expiresAt,
    now: new Date(),
    hasExpired: new Date() > record.expiresAt
  });
  
  if (new Date() > record.expiresAt) {
    console.log(`[VERIFY OTP] ❌ OTP has expired`);
    await Otp.deleteOne({ _id: record._id });
    throw new AppError("OTP has expired", 400);
  }
  
  const inputHash = hashOTP(otp);
  const matches = timingSafeEqualHex(inputHash, record.otpHash);
  console.log(`[VERIFY OTP] Hash match: ${matches}`);
  
  if (!matches) {
    console.log(`[VERIFY OTP] ❌ Invalid OTP - hash mismatch`);
    throw new AppError("Invalid OTP", 401);
  }
  
  console.log(`[VERIFY OTP] ✓ OTP verified successfully`);
  return record;
};

/* ===================== ROOT ROUTE ===================== */

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Child Location Tracking API",
    version: "1.0.0",
    endpoints: {
      health: "/health",
      auth: {
        signup: "/signup/send-otp",
        signupVerify: "/signup/verify-otp",
        signupResend: "/signup/resend-otp",
        login: "/login",
        loginVerify: "/login/verify-otp",
        loginResend: "/login/resend-otp"
      },
      child: {
        register: "/register-child",
        verify: "/verify-parent",
        list: "/my-children",
        remove: "/remove-child/:childPhone"
      },
      location: {
        update: "/update-location",
        track: "/track-location",
        history: "/location-history/:childPhone"
      },
      user: {
        profile: "/profile",
        changePassword: "/change-password"
      }
    }
  });
});

// ADMIN SECURITY ROUTES
app.post("/admin/sign", verifyToken, requireRole("Admin"), (req, res) => {
  if (!serverSigner) return res.status(503).json({ success: false, error: "Signer not ready" });
  const signature = serverSigner.sign(JSON.stringify(req.body));
  res.json({ success: true, signature, publicKey: serverSigner.getPublicKey() });
});

app.post("/admin/verify", verifyToken, requireRole("Admin"), (req, res) => {
  const { document, signature, publicKey } = req.body;
  const valid = RSASignature.verify(JSON.stringify(document), signature, publicKey);
  res.json({ success: true, valid });
});

/* ===================== AUTH ROUTES ===================== */

// Signup - Send OTP
app.post("/signup/send-otp", authLimiter, otpLimiter, asyncHandler(async (req, res) => {
  let { username, password, phone } = req.body;
  
  username = sanitizeInput(username);
  phone = sanitizeInput(phone);
  
  if (!username || !password || !phone) {
    throw new AppError("Username, password, and phone are required", 400);
  }
  
  const usernameCheck = validateUsername(username);
  if (!usernameCheck.valid) throw new AppError(usernameCheck.error, 400);
  
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid) throw new AppError(passwordCheck.error, 400);
  
  if (!validatePhone(phone)) throw new AppError("Invalid phone number format", 400);
  
  const existingUser = await User.findOne({ $or: [{ username }, { phone }] });
  if (existingUser) throw new AppError("Username or phone already registered", 409);
  
  // Hash password with salt of CONFIG.SALT_BYTES
  const salt = crypto.randomBytes(CONFIG.SALT_BYTES).toString("hex");
  const passwordHash = hashPassword(password, salt);
  
  console.log(`[SIGNUP] Generated salt length: ${salt.length} hex chars (${CONFIG.SALT_BYTES} bytes)`);
  console.log(`[SIGNUP] Generated passwordHash length: ${passwordHash.length}`);
  
  const otp = await createOTP(phone, "signup", {
    pendingUser: { username, passwordHash, salt, role: "Parent" }
  });
  
  res.json({
    success: true,
    phone,
    phoneHint: phone.slice(-4),
    message: "OTP sent to your phone",
    ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && { _dev_otp: otp, _dev_note: 'OTP included for development testing only' })
  });
}));

// Signup - Resend OTP
app.post("/signup/resend-otp", otpLimiter, asyncHandler(async (req, res) => {
  let { phone } = req.body;
  phone = sanitizeInput(phone);
  
  if (!phone) throw new AppError("Phone number is required", 400);
  
  const record = await Otp.findOne({
    phone,
    type: "signup",
    pendingUser: { $exists: true }
  }).sort({ createdAt: -1 });
  
  if (!record) throw new AppError("No pending signup found. Please start signup again.", 400);
  
  const otp = generateOTP();
  const otpHash = hashOTP(otp);
  
  try {
    await sendSMS(phone, `Your verification code is: ${otp}. Valid for ${Math.floor(CONFIG.OTP_EXPIRY / 1000)} seconds.`);
    record.otpHash = otpHash;
    record.expiresAt = new Date(Date.now() + CONFIG.OTP_EXPIRY);
    await record.save();
    res.json({ success: true, message: "OTP resent successfully", ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && { _dev_otp: otp }) });
  } catch (err) {
    throw new AppError(`Unable to resend OTP: ${err.message}`, 503);
  }
}));

// Signup - Verify OTP
app.post("/signup/verify-otp", authLimiter, asyncHandler(async (req, res) => {
  let { phone, otp } = req.body;
  phone = sanitizeInput(phone);
  otp = sanitizeInput(otp);
  
  if (!phone || !otp) throw new AppError("Phone and OTP are required", 400);
  
  const record = await verifyOTP(phone, otp, "signup");
  if (!record.pendingUser) throw new AppError("Invalid signup session", 400);
  
  const user = await User.create({
    username: record.pendingUser.username,
    passwordHash: record.pendingUser.passwordHash,
    salt: record.pendingUser.salt,
    phone,
    role: record.pendingUser.role,
    verified: true
  });
  
  await Otp.deleteOne({ _id: record._id });
  
  const token = generateToken({ userId: user._id, username: user.username, role: user.role, phone: user.phone });
  res.status(201).json({ success: true, message: "Account created successfully", token, user: { id: user._id, username: user.username, phone: user.phone, role: user.role } });
}));

/* ===================== LOGIN ROUTES ===================== */

// Login - Send OTP
app.post("/login", authLimiter, otpLimiter, asyncHandler(async (req, res) => {
  let { username, password } = req.body;
  username = sanitizeInput(username);
  
  if (!username || !password) throw new AppError("Username and password are required", 400);
  
  const user = await User.findOne({ username });
  if (!user) throw new AppError("Invalid credentials", 401);
  
  const passwordHash = hashPassword(password, user.salt);
  // Use timing-safe comparison
  if (!timingSafeEqualHex(passwordHash, user.passwordHash)) {
    console.log(`[LOGIN] Invalid password for user: ${username}`);
    throw new AppError("Invalid credentials", 401);
  }
  
  console.log(`[LOGIN] ✓ Password verified for user: ${username}`);
  
  const otp = await createOTP(user.phone, "login", { userId: user._id });
  
  res.json({ success: true, phone: user.phone, phoneHint: user.phone.slice(-4), message: "OTP sent to your phone", ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && { _dev_otp: otp }) });
}));

// Login - Resend OTP
app.post("/login/resend-otp", otpLimiter, asyncHandler(async (req, res) => {
  let { phone } = req.body;
  phone = sanitizeInput(phone);
  
  if (!phone) throw new AppError("Phone number is required", 400);
  
  const record = await Otp.findOne({
    phone,
    type: "login",
    userId: { $exists: true }
  }).sort({ createdAt: -1 });
  
  if (!record) throw new AppError("No pending login found. Please login again.", 400);
  
  const otp = generateOTP();
  const otpHash = hashOTP(otp);
  
  try {
    await sendSMS(phone, `Your login code is: ${otp}. Valid for ${Math.floor(CONFIG.OTP_EXPIRY / 1000)} seconds.`);
    record.otpHash = otpHash;
    record.expiresAt = new Date(Date.now() + CONFIG.OTP_EXPIRY);
    await record.save();
    res.json({ success: true, message: "OTP resent successfully", ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && { _dev_otp: otp }) });
  } catch (err) {
    throw new AppError(`Unable to resend OTP: ${err.message}`, 503);
  }
}));

// Login - Verify OTP
app.post("/login/verify-otp", authLimiter, asyncHandler(async (req, res) => {
  let { phone, otp } = req.body;
  phone = sanitizeInput(phone);
  otp = sanitizeInput(otp);
  
  if (!phone || !otp) throw new AppError("Phone and OTP are required", 400);
  
  const record = await verifyOTP(phone, otp, "login");
  if (!record.userId) throw new AppError("Invalid login session", 400);
  
  const user = await User.findById(record.userId);
  if (!user) throw new AppError("User not found", 404);
  
  await Otp.deleteOne({ _id: record._id });
  
  const token = generateToken({ userId: user._id, username: user.username, role: user.role, phone: user.phone });
  res.json({ success: true, message: "Login successful", token, user: { id: user._id, username: user.username, phone: user.phone, role: user.role } });
}));

/* ===================== CHILD REGISTRATION ===================== */

/* ===================== CHILD REGISTRATION ===================== */

// Register child - Send OTP to CHILD's phone (not parent)
app.post("/register-child", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  let { childPhone, childName } = req.body;
  childPhone = sanitizeInput(childPhone);
  childName = sanitizeInput(childName);
  
  const parentPhone = req.user.phone;
  
  if (!childPhone || !childName) throw new AppError("Child phone and name are required", 400);
  if (!validatePhone(childPhone)) throw new AppError("Invalid child phone number", 400);
  if (childPhone === parentPhone) throw new AppError("Child phone cannot be same as parent phone", 400);
  
  const existing = await ParentChild.findOne({ parentPhone, childPhone });
  if (existing) throw new AppError("Child already registered", 409);
  
  // Send OTP to CHILD's phone, not parent's phone
  const otp = await createOTP(childPhone, "child-registration", { 
    pendingRegistration: { parentPhone, childPhone, childName } 
  });
  
  res.json({ 
    success: true, 
    message: "OTP sent to child's phone for verification", 
    childPhoneHint: childPhone.slice(-4),
    ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && { _dev_otp: otp }) 
  });
}));

// Verify child's OTP and complete child registration
app.post("/verify-parent", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  let { otp, childPhone } = req.body;
  otp = sanitizeInput(otp);
  childPhone = sanitizeInput(childPhone);
  const parentPhone = req.user.phone;
  
  if (!otp) throw new AppError("OTP is required", 400);
  if (!childPhone) throw new AppError("Child phone is required", 400);
  
  // Verify OTP from child's phone
  const record = await verifyOTP(childPhone, otp, "child-registration");
  if (!record.pendingRegistration) throw new AppError("Invalid registration session", 400);
  
  // Verify that the parent making the request matches the pending registration
  if (record.pendingRegistration.parentPhone !== parentPhone) {
    throw new AppError("Unauthorized: Registration was initiated by a different parent", 403);
  }
  
  const { childName } = record.pendingRegistration;
  await ParentChild.create({ parentPhone, childPhone, childName, createdAt: new Date() });
  await Otp.deleteOne({ _id: record._id });
  
  res.status(201).json({ 
    success: true, 
    message: "Child registered successfully", 
    child: { childPhone, childName } 
  });
}));

// Get all registered children for a parent
app.get("/my-children", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  const parentPhone = req.user.phone;
  const children = await ParentChild.find({ parentPhone }).select('childPhone childName createdAt');
  res.json({ success: true, children });
}));

// Remove a child
app.delete("/remove-child/:childPhone", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  const parentPhone = req.user.phone;
  const childPhone = sanitizeInput(req.params.childPhone);
  const result = await ParentChild.deleteOne({ parentPhone, childPhone });
  if (result.deletedCount === 0) throw new AppError("Child not found", 404);
  res.json({ success: true, message: "Child removed successfully" });
}));

/* ===================== LOCATION TRACKING ===================== */

// Update child location (device -> server)
app.post("/update-location", asyncHandler(async (req, res) => {
  let { childPhone, latitude, longitude, accuracy, timestamp } = req.body;
  childPhone = sanitizeInput(childPhone);
  
  if (!childPhone || latitude === undefined || longitude === undefined) {
    throw new AppError("Child phone, latitude, and longitude are required", 400);
  }
  
  const lat = parseFloat(latitude);
  const lon = parseFloat(longitude);
  
  if (isNaN(lat) || lat < -90 || lat > 90) {
    throw new AppError("Invalid latitude", 400);
  }
  if (isNaN(lon) || lon < -180 || lon > 180) {
    throw new AppError("Invalid longitude", 400);
  }
  
  console.log(`[UPDATE LOCATION] Received location for ${childPhone}: lat=${lat}, lon=${lon}`);
  
  // Encrypt location data using AES-GCM
  const encryptedLat = encrypt(lat.toString());
  const encryptedLon = encrypt(lon.toString());
  
  console.log(`[UPDATE LOCATION] Encrypted data lengths: lat=${encryptedLat.length}, lon=${encryptedLon.length}`);
  
  await ChildLocation.create({
    childPhone,
    latitude: encryptedLat,
    longitude: encryptedLon,
    accuracy: accuracy || null,
    timestamp: timestamp ? new Date(timestamp) : new Date(),
    createdAt: new Date()
  });
  
  console.log(`[UPDATE LOCATION] ✅ Location saved successfully`);
  
  res.json({ success: true, message: "Location updated successfully" });
}));

// Track child location (parent)
app.post("/track-location", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  let { childPhone } = req.body;
  childPhone = sanitizeInput(childPhone);
  const parentPhone = req.user.phone;
  
  if (!childPhone) throw new AppError("Child phone is required", 400);
  
  // Verify parent has access to this child
  const link = await ParentChild.findOne({ parentPhone, childPhone });
  if (!link) {
    throw new AppError("Unauthorized: Child not registered with your account", 403);
  }
  
  // Fetch latest location
  const location = await ChildLocation.findOne({ childPhone })
    .sort({ createdAt: -1 })
    .limit(1);
  
  if (!location) {
    throw new AppError("No location data available", 404);
  }
  
  console.log(`[TRACK LOCATION] Decrypting location for ${childPhone}`);
  console.log(`[TRACK LOCATION] Encrypted data: lat length=${location.latitude.length}, lon length=${location.longitude.length}`);
  
  try {
    // Decrypt location data
    const latitude = decrypt(location.latitude);
    const longitude = decrypt(location.longitude);
    
    console.log(`[TRACK LOCATION] ✅ Decrypted successfully: lat=${latitude}, lon=${longitude}`);
    
    res.json({
      success: true,
      childName: link.childName,
      location: {
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        accuracy: location.accuracy,
        timestamp: location.timestamp || location.createdAt,
        lastUpdated: location.createdAt
      }
    });
  } catch (decryptError) {
    console.error(`[TRACK LOCATION] ❌ Decryption failed:`, decryptError);
    throw new AppError("Failed to decrypt location data. Data may be corrupted.", 500);
  }
}));

// Get location history
app.get("/location-history/:childPhone", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  const childPhone = sanitizeInput(req.params.childPhone);
  const parentPhone = req.user.phone;
  const limit = Math.min(parseInt(req.query.limit || "50", 10), 100);
  const skip = parseInt(req.query.skip || "0", 10);
  
  // Verify parent has access to this child
  const link = await ParentChild.findOne({ parentPhone, childPhone });
  if (!link) {
    throw new AppError("Unauthorized: Child not registered with your account", 403);
  }
  
  const locations = await ChildLocation.find({ childPhone })
    .sort({ createdAt: -1 })
    .limit(limit)
    .skip(skip);
  
  console.log(`[LOCATION HISTORY] Found ${locations.length} locations for ${childPhone}`);
  
  // Decrypt all locations
  const decryptedLocations = locations.map((loc, index) => {
    try {
      const lat = decrypt(loc.latitude);
      const lon = decrypt(loc.longitude);
      
      return {
        latitude: parseFloat(lat),
        longitude: parseFloat(lon),
        accuracy: loc.accuracy,
        timestamp: loc.timestamp || loc.createdAt
      };
    } catch (err) {
      console.error(`[LOCATION HISTORY] Failed to decrypt location ${index}:`, err);
      return null;
    }
  }).filter(loc => loc !== null); // Remove failed decryptions
  
  console.log(`[LOCATION HISTORY] Successfully decrypted ${decryptedLocations.length} locations`);
  
  res.json({
    success: true,
    childName: link.childName,
    locations: decryptedLocations,
    total: decryptedLocations.length
  });
}));

/* ===================== USER MANAGEMENT (IMPROVED WITH DEBUGGING) ===================== */

// Get current user profile
app.get("/profile", verifyToken, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('-passwordHash -salt');
  if (!user) throw new AppError("User not found", 404);
  res.json({ success: true, user: { id: user._id, username: user.username, phone: user.phone, role: user.role, verified: user.verified } });
}));

// Update user profile
app.patch("/profile", verifyToken, asyncHandler(async (req, res) => {
  const { username } = req.body;
  
  if (username) {
    const usernameCheck = validateUsername(username);
    if (!usernameCheck.valid) throw new AppError(usernameCheck.error, 400);
    
    const existing = await User.findOne({ username, _id: { $ne: req.user.userId } });
    if (existing) throw new AppError("Username already taken", 409);
  }
  
  const user = await User.findByIdAndUpdate(req.user.userId, { username }, { new: true, runValidators: true }).select('-passwordHash -salt');
  res.json({ success: true, message: "Profile updated", user });
}));

// Change password
app.post("/change-password", verifyToken, asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) throw new AppError("Current and new password are required", 400);
  
  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.valid) throw new AppError(passwordCheck.error, 400);
  
  const user = await User.findById(req.user.userId);
  if (!user) throw new AppError("User not found", 404);
  
  const currentHash = hashPassword(currentPassword, user.salt);
  if (!timingSafeEqualHex(currentHash, user.passwordHash)) throw new AppError("Current password is incorrect", 401);
  
  const newSalt = crypto.randomBytes(CONFIG.SALT_BYTES).toString("hex");
  const newHash = hashPassword(newPassword, newSalt);
  
  console.log(`[PASSWORD CHANGE] New salt length: ${newSalt.length} hex chars (${CONFIG.SALT_BYTES} bytes)`);
  console.log(`[PASSWORD CHANGE] New passwordHash length: ${newHash.length}`);
  
  user.passwordHash = newHash;
  user.salt = newSalt;
  await user.save();
  
  res.json({ success: true, message: "Password changed successfully" });
}));

// Forgot Password - Send OTP (IMPROVED WITH DETAILED LOGGING)
app.post("/forgot-password/send-otp", otpLimiter, asyncHandler(async (req, res) => {
  console.log('\n🔍 ===== FORGOT PASSWORD: SEND OTP REQUEST =====');
  console.log('📥 Raw request body:', req.body);
  
  let { username } = req.body;
  
  console.log('📝 Username before sanitization:', JSON.stringify(username));
  console.log('📝 Username type:', typeof username);
  console.log('📝 Username length:', username ? username.length : 0);
  
  // Check if sanitizeInput exists and is a function
  if (typeof sanitizeInput === 'function') {
    username = sanitizeInput(username);
    console.log('✅ Username after sanitization:', JSON.stringify(username));
  } else {
    console.warn('⚠️ sanitizeInput function not found, using raw username');
    username = username?.trim();
  }

  if (!username) {
    console.log('❌ Username validation failed: empty or null');
    throw new AppError("Username is required", 400);
  }

  console.log('🔍 Searching for user in database...');
  console.log('🔍 Query:', { username });
  
  const user = await User.findOne({ username });
  
  console.log('🔍 Database query result:', user ? 'USER FOUND ✅' : 'USER NOT FOUND ❌');
  
  if (user) {
    console.log('👤 User details:');
    console.log('   - ID:', user._id);
    console.log('   - Username:', user.username);
    console.log('   - Phone:', user.phone ? `${user.phone.substring(0, 3)}...${user.phone.slice(-4)}` : 'NO PHONE');
    console.log('   - Verified:', user.verified);
  } else {
    console.log('❌ No user found with username:', username);
    
    // Try to find similar usernames (case-insensitive)
    const similarUsers = await User.find({ 
      username: new RegExp(`^${username}$`, 'i') 
    }).limit(5);
    
    if (similarUsers.length > 0) {
      console.log('💡 Found similar usernames (case-insensitive):');
      similarUsers.forEach(u => console.log('   -', u.username));
    }
    
    throw new AppError("User not found", 404);
  }

  if (!user.phone) {
    console.log('❌ User exists but has no phone number');
    throw new AppError("User has no phone number registered", 400);
  }

  console.log('📱 Creating OTP for phone:', user.phone);
  
  const otp = await createOTP(user.phone, "forgot-password", {
    userId: user._id
  });

  console.log('✅ OTP created successfully:', otp);
  console.log('✅ Sending success response...');

  const response = {
    success: true,
    phone: user.phone,
    phoneHint: user.phone.slice(-4),
    message: "OTP sent to your registered phone"
  };

  // Add dev OTP in development mode
  if (process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS) {
    response._dev_otp = otp;
    console.log('🔓 DEV MODE: Including OTP in response:', otp);
  }

  console.log('📤 Response:', response);
  console.log('===== FORGOT PASSWORD: REQUEST COMPLETE =====\n');

  res.json(response);
}));

// Forgot Password - Verify OTP & Reset Password (IMPROVED WITH LOGGING)
app.post("/forgot-password/verify-otp", authLimiter, asyncHandler(async (req, res) => {
  console.log('\n🔍 ===== FORGOT PASSWORD: VERIFY OTP REQUEST =====');
  console.log('📥 Request body:', {
    phone: req.body.phone,
    otp: req.body.otp ? '****' + req.body.otp.slice(-2) : 'MISSING',
    newPassword: req.body.newPassword ? '[PROVIDED]' : '[MISSING]'
  });

  let { phone, otp, newPassword } = req.body;
  
  if (typeof sanitizeInput === 'function') {
    phone = sanitizeInput(phone);
    otp = sanitizeInput(otp);
  } else {
    phone = phone?.trim();
    otp = otp?.trim();
  }

  if (!phone || !otp || !newPassword) {
    console.log('❌ Missing required fields');
    throw new AppError("Phone, OTP and new password are required", 400);
  }

  console.log('🔐 Validating new password...');
  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.valid) {
    console.log('❌ Password validation failed:', passwordCheck.error);
    throw new AppError(passwordCheck.error, 400);
  }
  console.log('✅ Password validation passed');

  console.log('🔍 Verifying OTP...');
  const record = await verifyOTP(phone, otp, "forgot-password");
  console.log('✅ OTP verified, record:', record ? 'FOUND' : 'NOT FOUND');

  if (!record.userId) {
    console.log('❌ OTP record has no userId');
    throw new AppError("Invalid reset session", 400);
  }

  console.log('🔍 Finding user with ID:', record.userId);
  const user = await User.findById(record.userId);
  
  if (!user) {
    console.log('❌ User not found for ID:', record.userId);
    throw new AppError("User not found", 404);
  }
  console.log('✅ User found:', user.username);

  console.log('🔐 Generating new password hash...');
  const newSalt = crypto.randomBytes(CONFIG.SALT_BYTES).toString("hex");
  const newHash = hashPassword(newPassword, newSalt);

  console.log('💾 Updating user password...');
  user.passwordHash = newHash;
  user.salt = newSalt;
  await user.save();
  console.log('✅ Password updated successfully');

  console.log('🗑️ Deleting OTP record...');
  await Otp.deleteOne({ _id: record._id });
  console.log('✅ OTP record deleted');

  console.log('✅ Password reset successful for user:', user.username);
  console.log('===== FORGOT PASSWORD: VERIFY COMPLETE =====\n');

  res.json({ success: true, message: "Password reset successful. You can now login." });
}));

// Forgot Password - Resend OTP
app.post("/forgot-password/resend-otp", otpLimiter, asyncHandler(async (req, res) => {
  console.log('\n🔍 ===== FORGOT PASSWORD: RESEND OTP REQUEST =====');
  
  let { phone } = req.body;
  
  if (typeof sanitizeInput === 'function') {
    phone = sanitizeInput(phone);
  } else {
    phone = phone?.trim();
  }

  if (!phone) {
    console.log('❌ No phone provided');
    throw new AppError("Phone number is required", 400);
  }

  console.log('🔍 Looking for existing OTP record for phone:', phone);

  // Find existing forgot-password OTP record to get userId
  const existingOtp = await Otp.findOne({ 
    phone, 
    type: "forgot-password",
    expiresAt: { $gt: new Date() }
  });

  if (!existingOtp || !existingOtp.userId) {
    console.log('❌ No active password reset session found');
    throw new AppError("No active password reset session found. Please start over.", 400);
  }

  console.log('✅ Found existing session for user:', existingOtp.userId);

  // Delete old OTP
  console.log('🗑️ Deleting old OTP...');
  await Otp.deleteOne({ _id: existingOtp._id });

  // Create new OTP with same userId
  console.log('📱 Creating new OTP...');
  const otp = await createOTP(phone, "forgot-password", {
    userId: existingOtp.userId
  });

  console.log('✅ New OTP created:', otp);
  console.log('===== FORGOT PASSWORD: RESEND COMPLETE =====\n');

  res.json({
    success: true,
    message: "OTP resent successfully",
    ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && { _dev_otp: otp })
  });
}));

/* ===================== HEALTH CHECK ===================== */

app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    sms: {
      enabled: CONFIG.ENABLE_SMS,
      initialized: twilioClient !== null
    },
    encryption: {
      enabled: true,
      algorithm: "AES-256-GCM"
    }
  });
});

/* ===================== ERROR HANDLING ===================== */

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: "Route not found", path: req.path, method: req.method });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Error:", err);
  
  if (err.name === "ValidationError") {
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({ success: false, error: "Validation error", details: errors });
  }
  if (err.code === 11000) {
    return res.status(409).json({ success: false, error: "Duplicate entry", field: Object.keys(err.keyPattern || {})[0] });
  }
  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({ success: false, error: "Invalid token" });
  }
  if (err.name === "TokenExpiredError") {
    return res.status(401).json({ success: false, error: "Token expired" });
  }
  if (err.isOperational) {
    return res.status(err.statusCode).json({ success: false, error: err.message });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'Invalid JSON format' });
  }

  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    success: false,
    error: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,
    ...(process.env.NODE_ENV !== "production" && { stack: err.stack })
  });
});

/* ===================== START SERVER ===================== */

const startServer = (port) => {
  const server = app.listen(port, () => {
    console.log("\n" + "=".repeat(60));
    console.log("🚀 SERVER STARTED");
    console.log("=".repeat(60));
    console.log(`📍 Port: ${port}`);
    console.log(`🔒 JWT Auth: ${Boolean(process.env.JWT_SECRET) ? 'Enabled' : 'Using fallback secret'}`);
    console.log(`🔐 Encryption: AES-256-GCM Enabled`);
    console.log(`📱 SMS Service: ${CONFIG.ENABLE_SMS ? '✅ Enabled' : '❌ Disabled'}`);
    if (CONFIG.ENABLE_SMS) console.log(`📞 From Number: ${process.env.TWILIO_PHONE_NUMBER}`);
    console.log(`🔐 Environment: ${process.env.NODE_ENV || "development"}`);
    console.log(`🔑 Salt bytes: ${CONFIG.SALT_BYTES} bytes`);
    console.log("=".repeat(60) + "\n");
  }).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`⚠️  Port ${port} is busy, trying ${port + 1}...`);
      startServer(port + 1);
    } else {
      console.error('Server error:', err);
      process.exit(1);
    }
  });

  process.on("unhandledRejection", (err) => {
    console.error("UNHANDLED REJECTION! 💥 Shutting down...");
    console.error(err);
    server.close(() => process.exit(1));
  });

  return server;
};

startServer(CONFIG.PORT);
module.exports = app;