// cleanup-otps.js
// Run this script to clean up any corrupted OTP records in your database

require("dotenv").config();
const mongoose = require("mongoose");

const OtpSchema = new mongoose.Schema({
  phone: { type: String, required: true },
  otpHash: { type: String, required: true },
  type: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  pendingUser: { type: Object },
  userId: { type: mongoose.Schema.Types.ObjectId },
  pendingRegistration: { type: Object }
}, { timestamps: true });

const Otp = mongoose.model("Otp", OtpSchema);

async function cleanupOTPs() {
  try {
    console.log("🔌 Connecting to MongoDB...");
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log("✅ Connected to MongoDB");

    // Find all OTPs
    const allOtps = await Otp.find({});
    console.log(`\n📊 Found ${allOtps.length} OTP records`);

    // Show all OTPs
    console.log("\n🔍 Current OTP Records:");
    allOtps.forEach((otp, index) => {
      console.log(`\n${index + 1}. OTP Record:`);
      console.log(`   Phone: ${otp.phone}`);
      console.log(`   Type: ${otp.type || 'UNDEFINED ❌'}`);
      console.log(`   Expires: ${otp.expiresAt}`);
      console.log(`   Has pendingUser: ${!!otp.pendingUser}`);
      console.log(`   Has userId: ${!!otp.userId}`);
      console.log(`   Created: ${otp.createdAt}`);
    });

    // Find OTPs with undefined or null type
    const badOtps = await Otp.find({
      $or: [
        { type: { $exists: false } },
        { type: null },
        { type: undefined },
        { type: "" }
      ]
    });

    if (badOtps.length > 0) {
      console.log(`\n⚠️  Found ${badOtps.length} OTP(s) with missing or invalid type field`);
      
      // Delete all bad OTPs
      const result = await Otp.deleteMany({
        $or: [
          { type: { $exists: false } },
          { type: null },
          { type: undefined },
          { type: "" }
        ]
      });
      
      console.log(`✅ Deleted ${result.deletedCount} corrupted OTP record(s)`);
    } else {
      console.log("\n✅ No corrupted OTP records found");
    }

    // Option: Delete ALL OTPs (uncomment if you want a fresh start)
    // console.log("\n🧹 Deleting ALL OTP records for fresh start...");
    // const deleteResult = await Otp.deleteMany({});
    // console.log(`✅ Deleted ${deleteResult.deletedCount} OTP record(s)`);

    console.log("\n✨ Cleanup complete!");
    
  } catch (error) {
    console.error("❌ Error during cleanup:", error);
  } finally {
    await mongoose.connection.close();
    console.log("\n👋 Disconnected from MongoDB");
    process.exit(0);
  }
}

cleanupOTPs();