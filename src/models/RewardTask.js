// src/models/RewardTask.js
import mongoose from "mongoose";

const RewardTaskSchema = new mongoose.Schema(
  {
    familyId: { type: mongoose.Schema.Types.ObjectId, index: true },
    parentId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    title: { type: String, required: true, trim: true },
    description: { type: String, trim: true },

    category: { type: String, trim: true }, // e.g. "Homework", "Chores", "Sudden Quest"
    points: { type: Number, required: true, min: 0 },

    // "default" (pre-defined recurring) vs "sudden" (ad-hoc)
    type: { type: String, enum: ["default", "sudden"], default: "default" },

    // If true, completion auto-awards points without manual approval
    autoVerify: { type: Boolean, default: false },

    status: {
      type: String,
      enum: ["assigned", "accepted", "completed", "approved", "rejected"],
      default: "assigned",
      index: true,
    },

    dueAt: { type: Date },

    proofNote: { type: String, trim: true },
    proofPhotoUrl: { type: String, trim: true },

    completedAt: { type: Date },
    approvedAt: { type: Date },
    awardedAt: { type: Date }, // when points actually awarded to ledger
  },
  { timestamps: true }
);

export default mongoose.model("RewardTask", RewardTaskSchema, "reward_tasks");
