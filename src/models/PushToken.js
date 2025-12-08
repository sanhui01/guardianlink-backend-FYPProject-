// src/models/PushToken.js
import mongoose from "mongoose";

const PushTokenSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    familyId: { type: mongoose.Schema.Types.ObjectId, index: true },
    role: { type: String },      // "Parent" or "Child"
    deviceId: { type: String, index: true },
    fcmToken: { type: String, required: true },
    platform: { type: String, default: "android" },
  },
  { timestamps: true }
);

PushTokenSchema.index({ userId: 1, deviceId: 1 }, { unique: true });

export default mongoose.model("PushToken", PushTokenSchema, "push_tokens");
