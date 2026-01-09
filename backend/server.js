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
const ChildOtp = require("./models/ChildOtp");

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// Twilio Configuration
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

// Helper to send SMS
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

// ==================== AUTH ENDPOINTS ====================

app.post("/signup/send-otp", async (req, res) => {
  try {
    const { username, password, phone } = req.body;

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

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    const passwordHash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    await Otp.deleteMany({ phone: cleanPhone });

    await Otp.create({ 
      phone: cleanPhone, 
      otpHash,
      pendingUser: {
        username: username.trim().toLowerCase(),
        passwordHash
      },
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    console.log(`\n${"=".repeat(50)}`);
    console.log(`📝 SIGNUP OTP for ${cleanPhone}: ${otp}`);
    console.log(`⏰ Valid for 5 minutes`);
    console.log(`${"=".repeat(50)}\n`);

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

app.post("/signup/verify-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({ error: "Phone and OTP are required" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    const record = await Otp.findOne({ phone });
    
    if (!record) {
      return res.status(400).json({ error: "OTP not found or expired" });
    }

    if (!record.pendingUser) {
      return res.status(400).json({ error: "Invalid OTP request" });
    }

    if (record.expiresAt && record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone });
      return res.status(400).json({ error: "OTP has expired" });
    }

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    if (otpHash !== record.otpHash) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    await User.create({ 
      username: record.pendingUser.username, 
      passwordHash: record.pendingUser.passwordHash, 
      phone: phone,
      verified: true
    });

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

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" });
    }

    const user = await User.findOne({ 
      username: username.trim().toLowerCase() 
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const hash = crypto.createHash("sha256").update(password).digest("hex");
    if (hash !== user.passwordHash) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    await Otp.deleteMany({ phone: user.phone });

    await Otp.create({ 
      phone: user.phone, 
      otpHash,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    console.log(`\n${"=".repeat(50)}`);
    console.log(`🔐 LOGIN OTP for ${user.phone}: ${otp}`);
    console.log(`⏰ Valid for 5 minutes`);
    console.log(`${"=".repeat(50)}\n`);

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

app.post("/verify-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({ error: "Phone and OTP are required" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    const record = await Otp.findOne({ phone });
    
    if (!record) {
      return res.status(400).json({ error: "OTP not found or expired" });
    }

    if (record.pendingUser) {
      return res.status(400).json({ error: "Please use signup verification endpoint" });
    }

    if (record.expiresAt && record.expiresAt < new Date()) {
      await Otp.deleteOne({ phone });
      return res.status(400).json({ error: "OTP has expired" });
    }

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    if (otpHash !== record.otpHash) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

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

// ==================== PARENT-CHILD REGISTRATION ====================

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

    const existing = await ParentChild.findOne({
      parentPhone: cleanParentPhone,
      childPhone: cleanChildPhone
    });

    if (existing) {
      return res.status(409).json({ error: "This child is already registered" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

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

    // Find parent username from User collection
    const parentUser = await User.findOne({ phone: record.pendingRegistration.parentPhone });
    
    await ParentChild.create({
      parentUsername: parentUser ? parentUser.username : "unknown",
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

// ==================== LOCATION TRACKING ====================

// 1️⃣ PARENT REQUESTS CHILD TRACK (GENERATE CHILD OTP & SEND SMS)
app.post("/request-child-track", async (req, res) => {
  try {
    const { parentPhone, childPhone } = req.body;

    if (!parentPhone || !childPhone) {
      return res.status(400).json({ error: "Parent and child phone required" });
    }

    const cleanParentPhone = parentPhone.replace(/[\s-]/g, '');
    const cleanChildPhone = childPhone.replace(/[\s-]/g, '');

    // Verify parent-child relationship
    const link = await ParentChild.findOne({
      parentPhone: cleanParentPhone,
      childPhone: cleanChildPhone
    });

    if (!link) {
      return res.status(403).json({
        error: "Unauthorized parent-child access"
      });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    // Delete any existing OTPs for this child
    await ChildOtp.deleteMany({ childPhone: cleanChildPhone });

    // Store OTP with expiration
    const otpRecord = await ChildOtp.create({
      childPhone: cleanChildPhone,
      otpHash,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    console.log(`✅ OTP stored in database for child: ${cleanChildPhone}`);

    // Log to console
    console.log(`\n${"=".repeat(50)}`);
    console.log(`📱 CHILD TRACK OTP for ${cleanChildPhone}: ${otp}`);
    console.log(`👨‍👧 Requested by parent: ${cleanParentPhone}`);
    console.log(`⏰ Valid for 5 minutes`);
    console.log(`${"=".repeat(50)}\n`);

    // Send SMS to child
    const smsBody = `Your parent (${cleanParentPhone.slice(-4)}) has requested to track your location. Your verification code is ${otp}. Valid for 5 minutes. Open http://localhost:5173/child-gps.html to consent.`;
    const smsSent = await sendSMS(cleanChildPhone, smsBody);

    console.log(`\n📱 Send this link to child: http://localhost:5173/child-gps.html`);
    console.log(`📱 OTP for child (${cleanChildPhone}): ${otp}\n`);

    res.json({ 
      success: true,
      message: ENABLE_SMS && smsSent 
        ? `OTP sent to child's phone ending in ${cleanChildPhone.slice(-4)}`
        : `SMS disabled. OTP: ${otp}`,
      childPhone: cleanChildPhone,
      phoneHint: cleanChildPhone.slice(-4),
      smsEnabled: ENABLE_SMS,
      otp: ENABLE_SMS ? undefined : otp,  // Show OTP in response if SMS disabled
      gpsLink: "http://localhost:5173/child-gps.html",
      instructions: "Child should open the GPS link, enter parent's phone number and the OTP received"
    });
  } catch (err) {
    console.error("Request child track error:", err);
    res.status(500).json({ error: "Failed to generate child OTP" });
  }
});

// 2️⃣ CHILD VERIFIES WITH PARENT PHONE + OTP (CORRECT FLOW)
app.post("/verify-child-consent", async (req, res) => {
  try {
    const { parentPhone, otp } = req.body;

    if (!parentPhone || !otp) {
      return res.status(400).json({ error: "Parent phone and OTP required" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    const cleanParentPhone = parentPhone.replace(/[\s-]/g, '');

    // Step 1: Find parent-child relationship
    const parentChildLink = await ParentChild.findOne({ 
      parentPhone: cleanParentPhone 
    });

    if (!parentChildLink) {
      return res.status(403).json({ 
        error: "Parent-child relationship not found. Please register first." 
      });
    }

    const childPhone = parentChildLink.childPhone;

    // Step 2: Check if child has pending OTP
    const otpRecord = await ChildOtp.findOne({ childPhone: childPhone });
    
    if (!otpRecord) {
      return res.status(400).json({ 
        error: "No tracking request found. Ask your parent to request tracking again." 
      });
    }

    // Step 3: Check expiration
    if (otpRecord.expiresAt && otpRecord.expiresAt < new Date()) {
      await ChildOtp.deleteOne({ childPhone: childPhone });
      return res.status(400).json({ 
        error: "OTP has expired. Ask your parent to request tracking again." 
      });
    }

    // Step 4: Verify OTP hash
    const hash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    if (hash !== otpRecord.otpHash) {
      return res.status(401).json({ error: "Invalid OTP. Please check and try again." });
    }

    // Step 5: OTP verified - Delete it (one-time use)
    await ChildOtp.deleteOne({ childPhone: childPhone });

    console.log(`✅ Child consent verified - Parent: ${cleanParentPhone}, Child: ${childPhone}`);

    res.json({ 
      verified: true,
      childPhone: childPhone,
      parentPhone: cleanParentPhone,
      childName: parentChildLink.childName,
      message: "Consent verified. Location will be shared."
    });

  } catch (err) {
    console.error("Verify child consent error:", err);
    res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// 2️⃣ (OLD ENDPOINTS - KEEPING FOR BACKWARD COMPATIBILITY)
app.post("/verify-child-otp-with-parent", async (req, res) => {
  try {
    const { childPhone, otp } = req.body;

    if (!childPhone || !otp) {
      return res.status(400).json({ error: "Child phone and OTP required" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    const cleanChildPhone = childPhone.replace(/[\s-]/g, '');

    const record = await ChildOtp.findOne({ childPhone: cleanChildPhone });
    if (!record) {
      return res.status(400).json({ error: "OTP expired or not found. Ask your parent to request tracking again." });
    }

    if (record.expiresAt && record.expiresAt < new Date()) {
      await ChildOtp.deleteOne({ childPhone: cleanChildPhone });
      return res.status(400).json({ error: "OTP has expired. Ask your parent to request tracking again." });
    }

    const hash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    if (hash !== record.otpHash) {
      return res.status(401).json({ error: "Invalid OTP. Please check and try again." });
    }

    const parentChildLink = await ParentChild.findOne({ 
      childPhone: cleanChildPhone 
    });

    if (!parentChildLink) {
      return res.status(403).json({ 
        error: "No parent-child relationship found. Please register with your parent first." 
      });
    }

    await ChildOtp.deleteOne({ childPhone: cleanChildPhone });

    console.log(`✅ CHILD OTP verified for ${cleanChildPhone} - Parent: ${parentChildLink.parentPhone}`);

    res.json({ 
      verified: true,
      parentPhone: parentChildLink.parentPhone,
      parentName: parentChildLink.childName ? `Parent of ${parentChildLink.childName}` : "Your Parent",
      childName: parentChildLink.childName,
      message: "OTP verified successfully. You can now share your location."
    });
  } catch (err) {
    console.error("Verify child OTP error:", err);
    res.status(500).json({ error: "OTP verification failed" });
  }
});

// 2️⃣ (OLD) CHILD VERIFIES OTP (KEEPING FOR BACKWARD COMPATIBILITY)
app.post("/verify-child-otp", async (req, res) => {
  try {
    const { childPhone, otp } = req.body;

    if (!childPhone || !otp) {
      return res.status(400).json({ error: "Child phone and OTP required" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    const cleanChildPhone = childPhone.replace(/[\s-]/g, '');

    const record = await ChildOtp.findOne({ childPhone: cleanChildPhone });
    if (!record) {
      return res.status(400).json({ error: "OTP expired or not found" });
    }

    // Check expiration
    if (record.expiresAt && record.expiresAt < new Date()) {
      await ChildOtp.deleteOne({ childPhone: cleanChildPhone });
      return res.status(400).json({ error: "OTP has expired" });
    }

    // Verify OTP
    const hash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    if (hash !== record.otpHash) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    await ChildOtp.deleteOne({ childPhone: cleanChildPhone });

    console.log(`✅ CHILD OTP verified for ${cleanChildPhone} - Location access granted`);

    res.json({ 
      verified: true,
      message: "OTP verified successfully. You can now share your location."
    });
  } catch (err) {
    console.error("Verify child OTP error:", err);
    res.status(500).json({ error: "OTP verification failed" });
  }
});

// 3️⃣ CHILD SENDS LOCATION (STORE IN DB)
app.post("/update-location", async (req, res) => {
  try {
    const { childPhone, latitude, longitude, accuracy } = req.body;

    if (!childPhone || !latitude || !longitude) {
      return res.status(400).json({ 
        error: "Child phone, latitude, and longitude required" 
      });
    }

    const cleanChildPhone = childPhone.replace(/[\s-]/g, '');

    const link = await ParentChild.findOne({ childPhone: cleanChildPhone });
    if (!link) {
      return res.status(403).json({
        error: "Child not registered"
      });
    }

    await ChildLocation.create({
      childPhone: cleanChildPhone,
      latitude,
      longitude,
      accuracy
    });

    console.log(`📍 Location stored for ${cleanChildPhone}: ${latitude}, ${longitude}`);

    res.json({ message: "Location stored successfully" });
  } catch (err) {
    console.error("Update location error:", err);
    res.status(500).json({ error: "Failed to store location" });
  }
});

// 4️⃣ PARENT FETCHES CHILD LOCATION (AUTH CHECK)
app.post("/track-location", async (req, res) => {
  try {
    const { parentPhone, childPhone } = req.body;

    if (!parentPhone || !childPhone) {
      return res.status(400).json({ error: "Parent and child phone are required" });
    }

    const cleanParentPhone = parentPhone.replace(/[\s-]/g, '');
    const cleanChildPhone = childPhone.replace(/[\s-]/g, '');

    const relationship = await ParentChild.findOne({
      parentPhone: cleanParentPhone,
      childPhone: cleanChildPhone
    });

    if (!relationship) {
      return res.status(403).json({ error: "You are not authorized to track this child" });
    }

    const location = await ChildLocation.findOne({ childPhone: cleanChildPhone })
      .sort({ createdAt: -1 });

    if (!location) {
      return res.status(404).json({ error: "Location not available. Child needs to share location first." });
    }

    res.json({
      childName: relationship.childName,
      latitude: location.latitude,
      longitude: location.longitude,
      accuracy: location.accuracy,
      lastUpdated: location.createdAt
    });

  } catch (err) {
    console.error("Track location error:", err);
    res.status(500).json({ error: "Failed to fetch location" });
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