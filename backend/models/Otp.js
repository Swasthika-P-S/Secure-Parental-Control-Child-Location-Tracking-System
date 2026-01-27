// models/Otp.js
const mongoose = require("mongoose");

const OtpSchema = new mongoose.Schema(
  {
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      trim: true,
      index: true
    },
    otpHash: {
      type: String,
      required: [true, "OTP hash is required"]
    },
    type: {
      type: String,
      required: [true, "OTP type is required"],
      enum: ["signup", "login", "child-registration"],
      index: true
    },
    expiresAt: {
      type: Date,
      required: [true, "Expiry date is required"],
      index: true
    },
    // For signup flow - stores pending user data
    pendingUser: {
      type: {
        username: String,
        passwordHash: String,
        salt: String,
        role: String
      },
      required: false
    },
    // For login flow - references existing user
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: false
    },
    // For child registration - stores pending registration data
    pendingRegistration: {
      type: {
        parentPhone: String,
        childPhone: String,
        childName: String
      },
      required: false
    }
  },
  {
    timestamps: true
  }
);

// Compound index for efficient queries
OtpSchema.index({ phone: 1, type: 1 });

// Auto-delete expired OTPs (MongoDB TTL index)
OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Pre-save validation
OtpSchema.pre("save", function (next) {
  // Ensure type is always set
  if (!this.type) {
    return next(new Error("OTP type must be specified"));
  }
  
  // Validate type-specific data
  if (this.type === "signup" && !this.pendingUser) {
    return next(new Error("Signup OTP must have pendingUser data"));
  }
  
  if (this.type === "login" && !this.userId) {
    return next(new Error("Login OTP must have userId"));
  }
  
  if (this.type === "child-registration" && !this.pendingRegistration) {
    return next(new Error("Child registration OTP must have pendingRegistration data"));
  }
  
  next();
});

const Otp = mongoose.model("Otp", OtpSchema);

module.exports = Otp;