// models/ParentChild.js
const mongoose = require("mongoose");

const parentChildSchema = new mongoose.Schema({
  parentPhone: {
    type: String,
    required: true,
    index: true
  },
  childPhone: {
    type: String,
    required: true
  },
  childName: {
    type: String,
    required: true
  },
  verified: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Create compound index for faster lookups
parentChildSchema.index({ parentPhone: 1, childPhone: 1 }, { unique: true });

module.exports = mongoose.model("ParentChild", parentChildSchema);