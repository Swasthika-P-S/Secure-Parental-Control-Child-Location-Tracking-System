require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");
const twilio = require("twilio");

const User = require("./models/User");
const Otp = require("./models/Otp");
const ParentChild = require("./models/ParentChild");
const ChildLocation = require("./models/ChildLocation");

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// Twilio Configuration (optional - controlled by ENABLE_SMS flag)
const ENABLE_SMS = process.env.ENABLE_SMS === "true";
let twilioClient = null;

if (ENABLE_SMS) {
  try {
    twilioClient = new twilio(
      process.env.TWILIO_ACCOUNT_SID,
      process.env.TWILIO_AUTH_TOKEN
    );
    console.log("✅ Twilio SMS enabled");
  } catch (err) {
    console.log("⚠️ Twilio initialization failed - SMS disabled");
  }
} else {
  console.log("📱 SMS disabled - OTPs will be shown in console");
}

// Helper to send SMS (only if enabled)
const sendSMS = async (to, body) => {
  if (ENABLE_SMS && twilioClient) {
    try {
      await twilioClient.messages.create({
        body,
        from: process.env.TWILIO_PHONE_NUMBER,
        to
      });
      console.log(`✅ SMS sent to ${to}`);
      return true;
    } catch (error) {
      console.error("⚠️ SMS failed:", error.message);
      return false;
    }
  }
  return false;
};

// Validation helpers
const validateUsername = (username) => {
  if (!username || username.trim().length < 3) {
    return "Username must be at least 3 characters";
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return "Username can only contain letters, numbers, and underscores";
  }
  return null;
};

const validatePassword = (password) => {
  if (!password || password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;'`~]/.test(password)) {
    return "Password must be 8+ characters with uppercase, lowercase, number, and special character";
  }
  return null;
};

const validatePhone = (phone) => {
  if (!phone) {
    return "Phone number is required";
  }
  const cleaned = phone.replace(/[\s-]/g, '');
  if (!/^\+[1-9]\d{9,14}$/.test(cleaned)) {
    return "Phone must be in format +[country code][number] (e.g., +911234567890)";
  }
  return null;
};

// STEP 1: INITIATE SIGNUP (Send OTP)
app.post("/signup/send-otp", async (req, res) => {
  try {
    const { username, password, phone } = req.body;

    // Validate inputs
    const usernameError = validateUsername(username);
    if (usernameError) {
      return res.status(400).json({ error: usernameError });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const phoneError = validatePhone(phone);
    if (phoneError) {
      return res.status(400).json({ error: phoneError });
    }

    const cleanPhone = phone.replace(/[\s-]/g, '');

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [
        { username: username.trim().toLowerCase() },
        { phone: cleanPhone }
      ]
    });

    if (existingUser) {
      if (existingUser.username === username.trim().toLowerCase()) {
        return res.status(409).json({ error: "Username already taken" });
      }
      return res.status(409).json({ error: "Phone number already registered" });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    // Store password hash temporarily with OTP
    const passwordHash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    // Delete any existing OTP for this phone
    await Otp.deleteMany({ phone: cleanPhone });

    // Store OTP with pending user data
    await Otp.create({ 
      phone: cleanPhone, 
      otpHash,
      pendingUser: {
        username: username.trim().toLowerCase(),
        passwordHash
      },
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    // Log OTP to console
    console.log(`\n${"=".repeat(50)}`);
    console.log(`📝 SIGNUP OTP for ${cleanPhone}: ${otp}`);
    console.log(`⏰ Valid for 5 minutes`);
    console.log(`${"=".repeat(50)}\n`);

    // Send OTP via SMS (if enabled)
    await sendSMS(cleanPhone, `Your signup verification code is ${otp}. Valid for 5 minutes.`);

    res.json({
      phone: cleanPhone,
      phoneHint: cleanPhone.slice(-4),
      message: ENABLE_SMS ? "OTP sent to your phone" : "Check console for OTP"
    });

  } catch (err) {
    console.error("Signup OTP error:", err);
    res.status(500).json({ error: "Failed to send OTP. Please try again." });
  }
});

// STEP 2: VERIFY OTP & COMPLETE SIGNUP
app.post("/signup/verify-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({ error: "Phone and OTP are required" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    // Find OTP record
    const record = await Otp.findOne({ phone });
    
    if (!record) {
      return res.status(400).json({ error: "OTP not found or expired" });
    }

    // Check if it has pending user data
    if (!record.pendingUser) {
      return res.status(400).json({ error: "Invalid OTP request" });
    }

    // Check expiry
    if (record.expiresAt && record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone });
      return res.status(400).json({ error: "OTP has expired" });
    }

    // Verify OTP
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    if (otpHash !== record.otpHash) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    // Create user account
    await User.create({ 
      username: record.pendingUser.username, 
      passwordHash: record.pendingUser.passwordHash, 
      phone: phone,
      verified: true
    });

    // Delete OTP record
    await Otp.deleteOne({ phone });

    console.log(`✅ User created and verified: ${record.pendingUser.username} (${phone})`);

    res.status(201).json({ 
      success: true,
      message: "Account created successfully! You can now login." 
    });

  } catch (err) {
    console.error("Signup verification error:", err);
    res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// LOGIN → SEND OTP
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" });
    }

    // Find user (case insensitive)
    const user = await User.findOne({ 
      username: username.trim().toLowerCase() 
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Verify password
    const hash = crypto.createHash("sha256").update(password).digest("hex");
    if (hash !== user.passwordHash) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    // Delete any existing OTP for this phone
    await Otp.deleteMany({ phone: user.phone });

    // Store new OTP (without pending user data for login)
    await Otp.create({ 
      phone: user.phone, 
      otpHash,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    // Log OTP to console
    console.log(`\n${"=".repeat(50)}`);
    console.log(`🔐 LOGIN OTP for ${user.phone}: ${otp}`);
    console.log(`⏰ Valid for 5 minutes`);
    console.log(`${"=".repeat(50)}\n`);

    // Send OTP via SMS (if enabled)
    await sendSMS(user.phone, `Your login verification code is ${otp}. Valid for 5 minutes.`);

    res.json({
      phone: user.phone,
      phoneHint: user.phone.slice(-4),
      message: ENABLE_SMS ? "OTP sent to your phone" : "Check console for OTP"
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed. Please try again." });
  }
});

// VERIFY LOGIN OTP
app.post("/verify-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({ error: "Phone and OTP are required" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    // Find OTP record
    const record = await Otp.findOne({ phone });
    
    if (!record) {
      return res.status(400).json({ error: "OTP not found or expired" });
    }

    // Make sure this is a login OTP (no pending user data)
    if (record.pendingUser) {
      return res.status(400).json({ error: "Please use signup verification endpoint" });
    }

    // Check expiry
    if (record.expiresAt && record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone });
      return res.status(400).json({ error: "OTP has expired" });
    }

    // Verify OTP
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    if (otpHash !== record.otpHash) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    // Delete OTP after successful verification
    await Otp.deleteOne({ phone });

    console.log(`✅ Login OTP verified for ${phone}`);

    res.json({ 
      success: true,
      message: "Login successful" 
    });

  } catch (err) {
    console.error("Login verification error:", err);
    res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// REGISTER PARENT-CHILD RELATIONSHIP (One-time setup with OTP)
app.post("/register-child", async (req, res) => {
  try {
    const { parentPhone, childPhone, childName } = req.body;

    if (!parentPhone || !childPhone || !childName) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const phoneError = validatePhone(parentPhone) || validatePhone(childPhone);
    if (phoneError) {
      return res.status(400).json({ error: phoneError });
    }

    const cleanParentPhone = parentPhone.replace(/[\s-]/g, '');
    const cleanChildPhone = childPhone.replace(/[\s-]/g, '');

    // Check if relationship already exists
    const existing = await ParentChild.findOne({
      parentPhone: cleanParentPhone,
      childPhone: cleanChildPhone
    });

    if (existing) {
      return res.status(409).json({ error: "This child is already registered" });
    }

    // Generate OTP for parent verification
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    // Store OTP with pending registration data
    await Otp.deleteMany({ phone: cleanParentPhone });
    await Otp.create({
      phone: cleanParentPhone,
      otpHash,
      pendingRegistration: {
        parentPhone: cleanParentPhone,
        childPhone: cleanChildPhone,
        childName
      },
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    console.log(`\n${"=".repeat(50)}`);
    console.log(`📝 PARENT VERIFICATION OTP: ${otp}`);
    console.log(`Parent: ${cleanParentPhone}, Child: ${cleanChildPhone}`);
    console.log(`${"=".repeat(50)}\n`);

    await sendSMS(cleanParentPhone, `Your verification code for registering ${childName} is ${otp}. Valid for 5 minutes.`);

    res.json({
      phone: cleanParentPhone,
      phoneHint: cleanParentPhone.slice(-4),
      message: ENABLE_SMS ? "OTP sent to parent's phone" : "Check console for OTP"
    });

  } catch (err) {
    console.error("Register child error:", err);
    res.status(500).json({ error: "Registration failed. Please try again." });
  }
});

// VERIFY PARENT & COMPLETE REGISTRATION
app.post("/verify-parent", async (req, res) => {
  try {
    const { parentPhone, otp } = req.body;

    if (!parentPhone || !otp) {
      return res.status(400).json({ error: "Phone and OTP are required" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    const cleanParentPhone = parentPhone.replace(/[\s-]/g, '');
    const record = await Otp.findOne({ phone: cleanParentPhone });

    if (!record || !record.pendingRegistration) {
      return res.status(400).json({ error: "OTP not found or expired" });
    }

    if (record.expiresAt && record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone: cleanParentPhone });
      return res.status(400).json({ error: "OTP has expired" });
    }

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    if (otpHash !== record.otpHash) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    // Create parent-child relationship
    await ParentChild.create({
      parentPhone: record.pendingRegistration.parentPhone,
      childPhone: record.pendingRegistration.childPhone,
      childName: record.pendingRegistration.childName,
      verified: true
    });

    await Otp.deleteOne({ phone: cleanParentPhone });

    console.log(`✅ Parent-Child relationship created: ${cleanParentPhone} -> ${record.pendingRegistration.childPhone}`);

    res.json({
      success: true,
      message: "Child registered successfully! You can now track their location."
    });

  } catch (err) {
    console.error("Verify parent error:", err);
    res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// GET PARENT'S REGISTERED CHILDREN
app.post("/my-children", async (req, res) => {
  try {
    const { parentPhone } = req.body;

    if (!parentPhone) {
      return res.status(400).json({ error: "Parent phone is required" });
    }

    const cleanParentPhone = parentPhone.replace(/[\s-]/g, '');
    const children = await ParentChild.find({ parentPhone: cleanParentPhone });

    res.json({
      children: children.map(child => ({
        childPhone: child.childPhone,
        childName: child.childName,
        registeredAt: child.createdAt
      }))
    });

  } catch (err) {
    console.error("Get children error:", err);
    res.status(500).json({ error: "Failed to fetch children" });
  }
});

// GET CHILD'S LOCATION
app.post("/track-location", async (req, res) => {
  try {
    const { parentPhone, childPhone } = req.body;

    if (!parentPhone || !childPhone) {
      return res.status(400).json({ error: "Parent and child phone are required" });
    }

    const cleanParentPhone = parentPhone.replace(/[\s-]/g, '');
    const cleanChildPhone = childPhone.replace(/[\s-]/g, '');

    // Verify parent-child relationship
    const relationship = await ParentChild.findOne({
      parentPhone: cleanParentPhone,
      childPhone: cleanChildPhone
    });

    if (!relationship) {
      return res.status(403).json({ error: "You are not authorized to track this child" });
    }

    // Get child's location
    const location = await ChildLocation.findOne({ childPhone: cleanChildPhone });

    if (!location) {
      return res.status(404).json({ error: "Location not available. Child needs to share location first." });
    }

    res.json({
      childName: relationship.childName,
      latitude: location.latitude,
      longitude: location.longitude,
      address: location.address,
      lastUpdated: location.lastUpdated
    });

  } catch (err) {
    console.error("Track location error:", err);
    res.status(500).json({ error: "Failed to fetch location" });
  }
});

// UPDATE CHILD'S LOCATION (Called from child's device)
app.post("/update-location", async (req, res) => {
  try {
    const { childPhone, latitude, longitude, address } = req.body;

    if (!childPhone || !latitude || !longitude) {
      return res.status(400).json({ error: "Child phone, latitude, and longitude are required" });
    }

    const cleanChildPhone = childPhone.replace(/[\s-]/g, '');

    await ChildLocation.findOneAndUpdate(
      { childPhone: cleanChildPhone },
      {
        latitude,
        longitude,
        address: address || "",
        lastUpdated: new Date()
      },
      { upsert: true, new: true }
    );

    console.log(`📍 Location updated for ${cleanChildPhone}: ${latitude}, ${longitude}`);

    res.json({ success: true, message: "Location updated" });

  } catch (err) {
    console.error("Update location error:", err);
    res.status(500).json({ error: "Failed to update location" });
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({ 
    status: "OK", 
    smsEnabled: ENABLE_SMS,
    timestamp: new Date() 
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 SMS: ${ENABLE_SMS ? "ENABLED" : "DISABLED (console only)"}`);
});