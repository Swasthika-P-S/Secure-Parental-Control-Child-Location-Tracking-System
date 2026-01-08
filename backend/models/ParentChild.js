const mongoose = require("mongoose");

const ParentChildSchema = new mongoose.Schema(
  {
    parentUsername: {
      type: String,
      required: true,
      index: true
    },

    childName: {
      type: String,
      required: true
    },

    childPhone: {
      type: String,
      required: true,
      index: true
    }
  },
  {
    timestamps: true
  }
);

// One parent cannot register the same child twice
ParentChildSchema.index(
  { parentUsername: 1, childPhone: 1 },
  { unique: true }
);

module.exports = mongoose.model("ParentChild", ParentChildSchema);
