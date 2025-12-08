// src/models/RewardRedemption.js
import mongoose from "mongoose";

const RewardRedemptionSchema = new mongoose.Schema(
  {
    familyId: { type: mongoose.Schema.Types.ObjectId, index: true },
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    // who triggered the redemption (could be parent or child)
    requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },

    // "screen_time", "app_unlock", "custom", etc.
    rewardType: { type: String, trim: true },

    label: { type: String, required: true, trim: true },
    costPoints: { type: Number, required: true, min: 1 },

    // payload is flexible: { bonusMinutes, packageName, note }
    payload: {
      bonusMinutes: { type: Number },
      packageName: { type: String, trim: true },
      note: { type: String, trim: true },
    },
  },
  { timestamps: true }
);

export default mongoose.model("RewardRedemption", RewardRedemptionSchema, "reward_redemptions");
