// models/ChildLocation.js
const mongoose = require("mongoose");

const childLocationSchema = new mongoose.Schema({
  childPhone: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  latitude: {
    type: Number,
    required: true
  },
  longitude: {
    type: Number,
    required: true
  },
  address: {
    type: String,
    default: ""
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("ChildLocation", childLocationSchema);