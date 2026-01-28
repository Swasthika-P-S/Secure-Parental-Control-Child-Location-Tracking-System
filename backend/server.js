require("dotenv").config({ path: __dirname + '/.env' });
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");
const twilio = require("twilio");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");

const User = require("./models/User");
const Otp = require("./models/Otp");
const ParentChild = require("./models/ParentChild");
const ChildLocation = require("./models/ChildLocation");

const app = express();

/* ===================== CONFIGURATION ===================== */
const CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex"),
  JWT_EXPIRES_IN: "7d",
  OTP_EXPIRY: 5 * 60 * 1000, // 5 minutes
  OTP_LENGTH: 6,
  SALT_ROUNDS: 8, // 8 bytes = 16 hex characters
  PBKDF2_ITERATIONS: 100000,
  AES_KEY: process.env.AES_KEY 
    ? Buffer.from(process.env.AES_KEY, "hex") 
    : crypto.randomBytes(32),
  PORT: process.env.PORT || 5001,
  ENABLE_SMS: process.env.ENABLE_SMS === "true"
};

// Warning for production
if (!process.env.JWT_SECRET) {
  console.warn("⚠️  WARNING: Using random JWT_SECRET. Sessions will reset on restart!");
}
if (!process.env.AES_KEY) {
  console.warn("⚠️  WARNING: Using random AES_KEY. Encrypted data will be unreadable on restart!");
}

/* ===================== MIDDLEWARE ===================== */
app.use(helmet());

// CORS - More explicit configuration
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',') 
      : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:5500'];
    
    // Allow requests with no origin (like mobile apps or Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all in development, or set to false for strict mode
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Parse JSON with error handling
app.use(express.json({ 
  limit: '10kb',
  // Handle JSON parsing errors
  verify: (req, res, buf, encoding) => {
    try {
      JSON.parse(buf);
    } catch(e) {
      res.status(400).json({
        success: false,
        error: 'Invalid JSON format'
      });
      throw new Error('Invalid JSON');
    }
  }
}));

// Parse URL-encoded data
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Log all requests in development
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`, req.body);
    next();
  });
}

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(generalLimiter);

// Strict rate limit for OTP endpoints
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: { success: false, error: "Too many OTP requests, please try again later" },
  skipSuccessfulRequests: false
});

// Auth rate limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: "Too many authentication attempts, please try again later" }
});

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
  // If SMS is disabled
  if (!CONFIG.ENABLE_SMS) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`📱 [SMS DISABLED] OTP for ${to}:`);
    console.log(`Message: ${body}`);
    console.log('='.repeat(60) + '\n');
    
    // In development mode, allow the flow to continue
    if (process.env.NODE_ENV === 'development') {
      return { success: true, message: 'Development mode - check console for OTP' };
    }
    
    // In production, throw error if SMS is disabled
    throw new Error('SMS service is currently disabled. Please contact support.');
  }
  
  // If Twilio client not initialized
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
    
    // Provide user-friendly error messages based on Twilio error codes
    let userMessage = 'Failed to send SMS. Please try again.';
    
    if (err.code === 21211) {
      userMessage = 'Invalid phone number format. Please check and try again.';
    } else if (err.code === 21408) {
      userMessage = 'This phone number is not verified. Please verify it in your Twilio account.';
    } else if (err.code === 21610) {
      userMessage = 'Unable to send SMS to this number. It may have opted out.';
    } else if (err.code === 20003) {
      userMessage = 'SMS service authentication failed. Please contact support.';
    } else if (err.code === 21606) {
      userMessage = 'SMS service configuration error. Please contact support.';
    }
    
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

// AES Encryption/Decryption
const IV_LENGTH = 16;

const encrypt = (text) => {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv("aes-256-cbc", CONFIG.AES_KEY, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return `${iv.toString("hex")}:${encrypted}`;
  } catch (err) {
    console.error("Encryption error:", err);
    throw new Error("Encryption failed");
  }
};

const decrypt = (data) => {
  try {
    const [ivHex, encrypted] = data.split(":");
    if (!ivHex || !encrypted) throw new Error("Invalid encrypted data format");
    
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", CONFIG.AES_KEY, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (err) {
    console.error("Decryption error:", err);
    throw new Error("Decryption failed");
  }
};

// Password hashing
const hashPassword = (password, salt) => {
  return crypto
    .pbkdf2Sync(password, salt, CONFIG.PBKDF2_ITERATIONS, 64, "sha512")
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
  return crypto.createHash("sha256").update(otp).digest("hex");
};

// JWT token generation
const generateToken = (payload) => {
  return jwt.sign(payload, CONFIG.JWT_SECRET, {
    expiresIn: CONFIG.JWT_EXPIRES_IN
  });
};

// JWT verification middleware
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

// Role check middleware
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
  const phoneRegex = /^\+?[1-9]\d{1,14}$/; // E.164 format
  return phoneRegex.test(phone);
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

/* ===================== ERROR HANDLING ===================== */

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

/* ===================== OTP MANAGEMENT (IMPROVED) ===================== */

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
  
  console.log(`[CREATE OTP] ✓ OTP created:`, {
    phone: otpRecord.phone,
    type: otpRecord.type,
    otp: otp, // Log actual OTP for debugging
    expiresAt: otpRecord.expiresAt
  });
  
  // Try to send SMS
  try {
    await sendSMS(phone, `Your verification code is: ${otp}. Valid for 5 minutes.`);
    console.log(`[CREATE OTP] ✅ SMS sent successfully`);
  } catch (err) {
    // If SMS fails, delete the OTP record since user can't verify
    console.error(`[CREATE OTP] ❌ Failed to send SMS:`, err.message);
    await Otp.deleteOne({ _id: otpRecord._id });
    
    // Throw error with user-friendly message
    throw new AppError(`Unable to send OTP: ${err.message}`, 503);
  }
  
  return otp;
};

const verifyOTP = async (phone, otp, type = null) => {
  const query = { phone };
  if (type) query.type = type;
  
  console.log(`[VERIFY OTP] Looking for OTP with query:`, query);
  console.log(`[VERIFY OTP] Input OTP: ${otp}`);
  
  // Get the most recent OTP for this phone/type
  const record = await Otp.findOne(query).sort({ createdAt: -1 });
  
  if (!record) {
    console.log(`[VERIFY OTP] ❌ No OTP found for phone: ${phone}, type: ${type}`);
    // Check if there are any OTPs for this phone at all
    const anyOtp = await Otp.findOne({ phone });
    if (anyOtp) {
      console.log(`[VERIFY OTP] Found OTP with different type:`, anyOtp.type);
    }
    throw new AppError("OTP expired or not found", 400);
  }
  
  console.log(`[VERIFY OTP] Found OTP record:`, {
    phone: record.phone,
    type: record.type,
    expiresAt: record.expiresAt,
    currentTime: new Date(),
    hasExpired: new Date() > record.expiresAt
  });
  
  // Check if OTP has expired
  if (new Date() > record.expiresAt) {
    console.log(`[VERIFY OTP] ❌ OTP has expired`);
    await Otp.deleteOne({ _id: record._id });
    throw new AppError("OTP has expired", 400);
  }
  
  // Verify OTP hash
  const inputHash = hashOTP(otp);
  console.log(`[VERIFY OTP] Hash comparison:`, {
    inputHash: inputHash.substring(0, 20) + '...',
    storedHash: record.otpHash.substring(0, 20) + '...',
    match: inputHash === record.otpHash
  });
  
  if (inputHash !== record.otpHash) {
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

/* ===================== AUTH ROUTES ===================== */

// Signup - Send OTP
app.post("/signup/send-otp", authLimiter, otpLimiter, asyncHandler(async (req, res) => {
  let { username, password, phone } = req.body;
  
  // Sanitize inputs
  username = sanitizeInput(username);
  phone = sanitizeInput(phone);
  
  // Validate inputs
  if (!username || !password || !phone) {
    throw new AppError("Username, password, and phone are required", 400);
  }
  
  const usernameCheck = validateUsername(username);
  if (!usernameCheck.valid) {
    throw new AppError(usernameCheck.error, 400);
  }
  
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid) {
    throw new AppError(passwordCheck.error, 400);
  }
  
  if (!validatePhone(phone)) {
    throw new AppError("Invalid phone number format", 400);
  }
  
  // Check if user already exists
  const existingUser = await User.findOne({ $or: [{ username }, { phone }] });
  if (existingUser) {
    throw new AppError("Username or phone already registered", 409);
  }
  
  // Hash password with 16 character salt (8 bytes)
  const salt = crypto.randomBytes(CONFIG.SALT_ROUNDS).toString("hex");
  const passwordHash = hashPassword(password, salt);
  
  console.log(`[SIGNUP] Generated salt: ${salt} (length: ${salt.length})`);
  console.log(`[SIGNUP] Generated passwordHash: ${passwordHash} (length: ${passwordHash.length})`);
  
  // Create OTP - this will throw error if SMS fails
  const otp = await createOTP(phone, "signup", {
    pendingUser: { username, passwordHash, salt, role: "Parent" }
  });
  
  res.json({
    success: true,
    phone,
    phoneHint: phone.slice(-4),
    message: "OTP sent to your phone",
    // In development mode, include OTP for testing
    ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && {
      _dev_otp: otp,
      _dev_note: 'OTP included for development testing only'
    })
  });
}));

// Signup - Resend OTP
app.post("/signup/resend-otp", otpLimiter, asyncHandler(async (req, res) => {
  let { phone } = req.body;
  phone = sanitizeInput(phone);
  
  if (!phone) {
    throw new AppError("Phone number is required", 400);
  }
  
  console.log(`[SIGNUP RESEND] Resending OTP for phone: ${phone}`);
  
  // Find existing pending signup
  const record = await Otp.findOne({
    phone,
    type: "signup",
    pendingUser: { $exists: true }
  }).sort({ createdAt: -1 });
  
  if (!record) {
    console.log(`[SIGNUP RESEND] No pending signup found`);
    throw new AppError("No pending signup found. Please start signup again.", 400);
  }
  
  // Generate new OTP
  const otp = generateOTP();
  const otpHash = hashOTP(otp);
  
  // Try to send SMS before updating record
  try {
    await sendSMS(phone, `Your verification code is: ${otp}. Valid for 5 minutes.`);
    
    // Only update if SMS was sent successfully
    record.otpHash = otpHash;
    record.expiresAt = new Date(Date.now() + CONFIG.OTP_EXPIRY);
    await record.save();
    
    console.log(`[SIGNUP RESEND] ✅ New OTP sent: ${otp}`);
    
    res.json({
      success: true,
      message: "OTP resent successfully",
      ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && {
        _dev_otp: otp
      })
    });
  } catch (err) {
    console.error(`[SIGNUP RESEND] ❌ Failed to send SMS:`, err.message);
    throw new AppError(`Unable to resend OTP: ${err.message}`, 503);
  }
}));

// Signup - Verify OTP
app.post("/signup/verify-otp", authLimiter, asyncHandler(async (req, res) => {
  let { phone, otp } = req.body;
  phone = sanitizeInput(phone);
  otp = sanitizeInput(otp);
  
  console.log(`[SIGNUP VERIFY] Verifying OTP for phone: ${phone}, OTP: ${otp}`);
  
  if (!phone || !otp) {
    throw new AppError("Phone and OTP are required", 400);
  }
  
  // Verify OTP
  const record = await verifyOTP(phone, otp, "signup");
  
  if (!record.pendingUser) {
    throw new AppError("Invalid signup session", 400);
  }
  
  // Create user with exact format
  const user = await User.create({
    username: record.pendingUser.username,
    passwordHash: record.pendingUser.passwordHash,
    salt: record.pendingUser.salt,
    phone: phone,
    role: record.pendingUser.role,
    verified: true
  });
  
  console.log(`[SIGNUP VERIFY] ✓ User created:`, {
    username: user.username,
    salt: user.salt,
    saltLength: user.salt.length,
    passwordHashLength: user.passwordHash.length,
    phone: user.phone,
    role: user.role,
    verified: user.verified
  });
  
  // Delete OTP record
  await Otp.deleteOne({ _id: record._id });
  
  // Generate JWT token
  const token = generateToken({
    userId: user._id,
    username: user.username,
    role: user.role,
    phone: user.phone
  });
  
  res.status(201).json({
    success: true,
    message: "Account created successfully",
    token,
    user: {
      id: user._id,
      username: user.username,
      phone: user.phone,
      role: user.role
    }
  });
}));

/* ===================== LOGIN ROUTES ===================== */

// Login - Send OTP
app.post("/login", authLimiter, otpLimiter, asyncHandler(async (req, res) => {
  let { username, password } = req.body;
  username = sanitizeInput(username);
  
  console.log(`[LOGIN] Attempt for username: ${username}`);
  
  if (!username || !password) {
    throw new AppError("Username and password are required", 400);
  }
  
  // Find user
  const user = await User.findOne({ username });
  if (!user) {
    console.log(`[LOGIN] User not found: ${username}`);
    // Generic error to prevent user enumeration
    throw new AppError("Invalid credentials", 401);
  }
  
  // Verify password
  const passwordHash = hashPassword(password, user.salt);
  if (passwordHash !== user.passwordHash) {
    console.log(`[LOGIN] Invalid password for user: ${username}`);
    throw new AppError("Invalid credentials", 401);
  }
  
  console.log(`[LOGIN] ✓ Password verified for user: ${username}`);
  
  // Create OTP for login - this will throw error if SMS fails
  const otp = await createOTP(user.phone, "login", { userId: user._id });
  
  res.json({
    success: true,
    phone: user.phone,
    phoneHint: user.phone.slice(-4),
    message: "OTP sent to your phone",
    ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && {
      _dev_otp: otp
    })
  });
}));

// Login - Resend OTP
app.post("/login/resend-otp", otpLimiter, asyncHandler(async (req, res) => {
  let { phone } = req.body;
  phone = sanitizeInput(phone);
  
  console.log(`[LOGIN RESEND] Resending OTP for phone: ${phone}`);
  
  if (!phone) {
    throw new AppError("Phone number is required", 400);
  }
  
  // Find existing login OTP
  const record = await Otp.findOne({
    phone,
    type: "login",
    userId: { $exists: true }
  }).sort({ createdAt: -1 });
  
  if (!record) {
    console.log(`[LOGIN RESEND] No pending login found`);
    throw new AppError("No pending login found. Please login again.", 400);
  }
  
  // Generate new OTP
  const otp = generateOTP();
  const otpHash = hashOTP(otp);
  
  // Try to send SMS before updating record
  try {
    await sendSMS(phone, `Your login code is: ${otp}. Valid for 5 minutes.`);
    
    // Only update if SMS was sent successfully
    record.otpHash = otpHash;
    record.expiresAt = new Date(Date.now() + CONFIG.OTP_EXPIRY);
    await record.save();
    
    console.log(`[LOGIN RESEND] ✅ New OTP sent: ${otp}`);
    
    res.json({
      success: true,
      message: "OTP resent successfully",
      ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && {
        _dev_otp: otp
      })
    });
  } catch (err) {
    console.error(`[LOGIN RESEND] ❌ Failed to send SMS:`, err.message);
    throw new AppError(`Unable to resend OTP: ${err.message}`, 503);
  }
}));

// Login - Verify OTP
app.post("/login/verify-otp", authLimiter, asyncHandler(async (req, res) => {
  let { phone, otp } = req.body;
  phone = sanitizeInput(phone);
  otp = sanitizeInput(otp);
  
  console.log(`[LOGIN VERIFY] Verifying OTP for phone: ${phone}, OTP: ${otp}`);
  
  if (!phone || !otp) {
    throw new AppError("Phone and OTP are required", 400);
  }
  
  // Verify OTP
  const record = await verifyOTP(phone, otp, "login");
  
  if (!record.userId) {
    throw new AppError("Invalid login session", 400);
  }
  
  // Get user
  const user = await User.findById(record.userId);
  if (!user) {
    throw new AppError("User not found", 404);
  }
  
  console.log(`[LOGIN VERIFY] ✓ User logged in: ${user.username}`);
  
  // Delete OTP record
  await Otp.deleteOne({ _id: record._id });
  
  // Generate JWT token
  const token = generateToken({
    userId: user._id,
    username: user.username,
    role: user.role,
    phone: user.phone
  });
  
  res.json({
    success: true,
    message: "Login successful",
    token,
    user: {
      id: user._id,
      username: user.username,
      phone: user.phone,
      role: user.role
    }
  });
}));

/* ===================== CHILD REGISTRATION ===================== */

// Register child - Send OTP to parent
app.post("/register-child", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  let { childPhone, childName } = req.body;
  childPhone = sanitizeInput(childPhone);
  childName = sanitizeInput(childName);
  
  const parentPhone = req.user.phone;
  
  if (!childPhone || !childName) {
    throw new AppError("Child phone and name are required", 400);
  }
  
  if (!validatePhone(childPhone)) {
    throw new AppError("Invalid child phone number", 400);
  }
  
  if (childPhone === parentPhone) {
    throw new AppError("Child phone cannot be same as parent phone", 400);
  }
  
  // Check if child is already registered with this parent
  const existing = await ParentChild.findOne({ parentPhone, childPhone });
  if (existing) {
    throw new AppError("Child already registered", 409);
  }
  
  // Create OTP for parent verification - this will throw error if SMS fails
  const otp = await createOTP(parentPhone, "child-registration", {
    pendingRegistration: { parentPhone, childPhone, childName }
  });
  
  res.json({
    success: true,
    message: "OTP sent to parent phone for verification",
    ...(process.env.NODE_ENV === 'development' && !CONFIG.ENABLE_SMS && {
      _dev_otp: otp
    })
  });
}));

// Verify parent OTP and complete child registration
app.post("/verify-parent", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  let { otp } = req.body;
  otp = sanitizeInput(otp);
  
  const parentPhone = req.user.phone;
  
  if (!otp) {
    throw new AppError("OTP is required", 400);
  }
  
  // Verify OTP
  const record = await verifyOTP(parentPhone, otp, "child-registration");
  
  if (!record.pendingRegistration) {
    throw new AppError("Invalid registration session", 400);
  }
  
  const { childPhone, childName } = record.pendingRegistration;
  
  // Create parent-child link
  await ParentChild.create({
    parentPhone,
    childPhone,
    childName,
    createdAt: new Date()
  });
  
  // Delete OTP record
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
  
  res.json({
    success: true,
    children
  });
}));

// Remove a child
app.delete("/remove-child/:childPhone", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  const parentPhone = req.user.phone;
  const childPhone = sanitizeInput(req.params.childPhone);
  
  const result = await ParentChild.deleteOne({ parentPhone, childPhone });
  
  if (result.deletedCount === 0) {
    throw new AppError("Child not found", 404);
  }
  
  res.json({
    success: true,
    message: "Child removed successfully"
  });
}));

/* ===================== LOCATION TRACKING ===================== */

// Update child location
app.post("/update-location", asyncHandler(async (req, res) => {
  let { childPhone, latitude, longitude, accuracy, timestamp } = req.body;
  
  childPhone = sanitizeInput(childPhone);
  
  if (!childPhone || latitude === undefined || longitude === undefined) {
    throw new AppError("Child phone, latitude, and longitude are required", 400);
  }
  
  // Validate coordinates
  const lat = parseFloat(latitude);
  const lon = parseFloat(longitude);
  
  if (isNaN(lat) || lat < -90 || lat > 90) {
    throw new AppError("Invalid latitude", 400);
  }
  
  if (isNaN(lon) || lon < -180 || lon > 180) {
    throw new AppError("Invalid longitude", 400);
  }
  
  // Encrypt location data
  const encryptedLat = encrypt(lat.toString());
  const encryptedLon = encrypt(lon.toString());
  
  // Store location
  await ChildLocation.create({
    childPhone,
    latitude: encryptedLat,
    longitude: encryptedLon,
    accuracy: accuracy || null,
    timestamp: timestamp ? new Date(timestamp) : new Date()
  });
  
  res.json({
    success: true,
    message: "Location updated successfully"
  });
}));

// Track child location (parent)
app.post("/track-location", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  let { childPhone } = req.body;
  childPhone = sanitizeInput(childPhone);
  
  const parentPhone = req.user.phone;
  
  if (!childPhone) {
    throw new AppError("Child phone is required", 400);
  }
  
  // Verify parent-child relationship
  const link = await ParentChild.findOne({ parentPhone, childPhone });
  if (!link) {
    throw new AppError("Unauthorized: Child not registered with your account", 403);
  }
  
  // Get latest location
  const location = await ChildLocation.findOne({ childPhone })
    .sort({ createdAt: -1 })
    .limit(1);
  
  if (!location) {
    throw new AppError("No location data available", 404);
  }
  
  // Decrypt location
  const latitude = decrypt(location.latitude);
  const longitude = decrypt(location.longitude);
  
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
}));

// Get location history
app.get("/location-history/:childPhone", verifyToken, requireRole("Parent"), asyncHandler(async (req, res) => {
  const childPhone = sanitizeInput(req.params.childPhone);
  const parentPhone = req.user.phone;
  const limit = parseInt(req.query.limit) || 50;
  const skip = parseInt(req.query.skip) || 0;
  
  // Verify parent-child relationship
  const link = await ParentChild.findOne({ parentPhone, childPhone });
  if (!link) {
    throw new AppError("Unauthorized: Child not registered with your account", 403);
  }
  
  // Get location history
  const locations = await ChildLocation.find({ childPhone })
    .sort({ createdAt: -1 })
    .limit(Math.min(limit, 100))
    .skip(skip);
  
  // Decrypt and format locations
  const decryptedLocations = locations.map(loc => ({
    latitude: parseFloat(decrypt(loc.latitude)),
    longitude: parseFloat(decrypt(loc.longitude)),
    accuracy: loc.accuracy,
    timestamp: loc.timestamp || loc.createdAt
  }));
  
  res.json({
    success: true,
    childName: link.childName,
    locations: decryptedLocations,
    total: locations.length
  });
}));

/* ===================== USER MANAGEMENT ===================== */

// Get current user profile
app.get("/profile", verifyToken, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.userId).select('-passwordHash -salt');
  
  if (!user) {
    throw new AppError("User not found", 404);
  }
  
  res.json({
    success: true,
    user: {
      id: user._id,
      username: user.username,
      phone: user.phone,
      role: user.role,
      verified: user.verified
    }
  });
}));

// Update user profile
app.patch("/profile", verifyToken, asyncHandler(async (req, res) => {
  const { username } = req.body;
  
  if (username) {
    const usernameCheck = validateUsername(username);
    if (!usernameCheck.valid) {
      throw new AppError(usernameCheck.error, 400);
    }
    
    // Check if username is already taken
    const existing = await User.findOne({
      username,
      _id: { $ne: req.user.userId }
    });
    
    if (existing) {
      throw new AppError("Username already taken", 409);
    }
  }
  
  const user = await User.findByIdAndUpdate(
    req.user.userId,
    { username },
    { new: true, runValidators: true }
  ).select('-passwordHash -salt');
  
  res.json({
    success: true,
    message: "Profile updated",
    user
  });
}));

// Change password
app.post("/change-password", verifyToken, asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    throw new AppError("Current and new password are required", 400);
  }
  
  // Validate new password
  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.valid) {
    throw new AppError(passwordCheck.error, 400);
  }
  
  // Get user
  const user = await User.findById(req.user.userId);
  if (!user) {
    throw new AppError("User not found", 404);
  }
  
  // Verify current password
  const currentHash = hashPassword(currentPassword, user.salt);
  if (currentHash !== user.passwordHash) {
    throw new AppError("Current password is incorrect", 401);
  }
  
  // Hash new password with 16 character salt (8 bytes)
  const newSalt = crypto.randomBytes(CONFIG.SALT_ROUNDS).toString("hex");
  const newHash = hashPassword(newPassword, newSalt);
  
  console.log(`[PASSWORD CHANGE] New salt: ${newSalt} (length: ${newSalt.length})`);
  console.log(`[PASSWORD CHANGE] New passwordHash length: ${newHash.length}`);
  
  // Update password
  user.passwordHash = newHash;
  user.salt = newSalt;
  await user.save();
  
  res.json({
    success: true,
    message: "Password changed successfully"
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
    }
  });
});

/* ===================== ERROR HANDLING ===================== */

// 404 handler - MUST return JSON
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found",
    path: req.path,
    method: req.method
  });
});

// Global error handler - ALWAYS returns JSON
app.use((err, req, res, next) => {
  // Log error for debugging
  console.error("Error:", err);
  
  // Default error response
  let statusCode = 500;
  let errorMessage = "Internal server error";
  
  // Mongoose validation error
  if (err.name === "ValidationError") {
    statusCode = 400;
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(statusCode).json({
      success: false,
      error: "Validation error",
      details: errors
    });
  }
  
  // Mongoose duplicate key error
  if (err.code === 11000) {
    statusCode = 409;
    return res.status(statusCode).json({
      success: false,
      error: "Duplicate entry",
      field: Object.keys(err.keyPattern || {})[0]
    });
  }
  
  // JWT errors
  if (err.name === "JsonWebTokenError") {
    statusCode = 401;
    return res.status(statusCode).json({ 
      success: false,
      error: "Invalid token" 
    });
  }
  
  if (err.name === "TokenExpiredError") {
    statusCode = 401;
    return res.status(statusCode).json({ 
      success: false,
      error: "Token expired" 
    });
  }
  
  // Operational errors (AppError)
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      success: false,
      error: err.message
    });
  }
  
  // JSON parsing error
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      error: 'Invalid JSON format'
    });
  }
  
  // Generic programming or unknown errors
  res.status(statusCode).json({
    success: false,
    error: process.env.NODE_ENV === "production" 
      ? "Internal server error" 
      : err.message,
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
    console.log(`🔒 JWT Auth: Enabled`);
    console.log(`📱 SMS Service: ${CONFIG.ENABLE_SMS ? '✅ Enabled' : '❌ Disabled'}`);
    if (CONFIG.ENABLE_SMS) {
      console.log(`📲 Twilio Client: ${twilioClient ? '✅ Initialized' : '❌ Failed'}`);
      if (twilioClient) {
        console.log(`📞 From Number: ${process.env.TWILIO_PHONE_NUMBER}`);
      }
    }
    console.log(`🔐 Environment: ${process.env.NODE_ENV || "development"}`);
    console.log(`🌐 CORS: Configured`);
    console.log(`🔑 Salt length: 16 characters (8 bytes)`);
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

  // Handle unhandled promise rejections
  process.on("unhandledRejection", (err) => {
    console.error("UNHANDLED REJECTION! 💥 Shutting down...");
    console.error(err);
    server.close(() => {
      process.exit(1);
    });
  });

  return server;
};

startServer(CONFIG.PORT);
module.exports = app;