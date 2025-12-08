// src/models/RewardPointEntry.js
import mongoose from "mongoose";

const RewardPointEntrySchema = new mongoose.Schema(
  {
    familyId: { type: mongoose.Schema.Types.ObjectId, index: true },
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    // Optional link back to a specific task
    taskId: { type: mongoose.Schema.Types.ObjectId, ref: "RewardTask" },

    // "task", "diary", "redeem", etc.
    source: { type: String, trim: true },

    // +ve for earning, -ve for redemption
    delta: { type: Number, required: true },

    description: { type: String, trim: true },
  },
  { timestamps: true }
);

RewardPointEntrySchema.index({ childId: 1, createdAt: -1 });

export default mongoose.model("RewardPointEntry", RewardPointEntrySchema, "reward_point_entries");
