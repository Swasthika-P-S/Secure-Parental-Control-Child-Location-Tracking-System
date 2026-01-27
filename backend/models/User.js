// const mongoose = require("mongoose");

// const userSchema = new mongoose.Schema({
//   username: { type: String, required: true, unique: true },
//   passwordHash: { type: String, required: true },
//   phone: { type: String, required: true },
//   verified: { type: Boolean, default: false },
//   createdAt: { type: Date, default: Date.now }
// });

// module.exports = mongoose.model("User", userSchema);
const mongoose = require("mongoose");

module.exports = mongoose.model("User", new mongoose.Schema({
  username: String,
  passwordHash: String,
  salt: String,
  phone: String,
  role: String,
  verified: Boolean
}));
