const mongoose = require("mongoose");

const ChildLocationSchema = new mongoose.Schema(
  {
    childPhone: {
      type: String,
      required: true,
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

    accuracy: {
      type: Number,
      default: null
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("ChildLocation", ChildLocationSchema);
