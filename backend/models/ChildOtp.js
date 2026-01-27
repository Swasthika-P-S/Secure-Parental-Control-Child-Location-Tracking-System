// const mongoose = require("mongoose");

// const ChildOtpSchema = new mongoose.Schema({
//   childPhone: String,
//   otpHash: String,
//   createdAt: {
//     type: Date,
//     default: Date.now,
//     expires: 300
//   }
// });

// module.exports = mongoose.model("ChildOtp", ChildOtpSchema);
const mongoose = require("mongoose");

module.exports = mongoose.model("ChildOtp", new mongoose.Schema({
  childPhone: String,
  otpHash: String,
  expiresAt: Date
}));
