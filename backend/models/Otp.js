const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
  phone: { 
    type: String, 
    required: true,
    index: true
  },
  otpHash: { 
    type: String, 
    required: true 
  },
  // For signup: store pending user data
  pendingUser: {
    type: {
      username: String,
      passwordHash: String
    },
    required: false,
    default: null
  },
  // For parent-child registration: store pending registration data
  pendingRegistration: {
    type: {
      parentPhone: String,
      childPhone: String,
      childName: String
    },
    required: false,
    default: null
  },
  expiresAt: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    expires: 300 // Auto-delete after 5 minutes
  }
});

module.exports = mongoose.model("Otp", otpSchema);