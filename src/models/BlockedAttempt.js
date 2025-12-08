// src/models/BlockedAttempt.js
import mongoose from "mongoose";

const BlockedAttemptSchema = new mongoose.Schema({
  // Which child triggered the blocked attempt
  childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  // What type of block happened: website or app
  sourceType: { type: String, enum: ["web", "app"], required: true },
  
  // Web-specific
  url: {
    type: String,
    trim: true,
    required: function () { return this.sourceType === "web"; }
  },
  path: {
    type: String,
    trim: true,
    required: function () { return this.sourceType === "web"; }
  },

  // App-specific
  packageName: {
    type: String,
    trim: true,
    required: function () { return this.sourceType === "app"; }
  },

  reason: { type: String, trim: true },
  blockedAt: { type: Date, default: Date.now }
});

BlockedAttemptSchema.index({ childId: 1, blockedAt: -1 });

const BlockedAttempt = mongoose.model("BlockedAttempt", BlockedAttemptSchema, "blocked_attempts");
export default BlockedAttempt;
