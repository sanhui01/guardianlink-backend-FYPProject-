// src/models/KeywordEntry.js
import mongoose from "mongoose";

const KeywordEntrySchema = new mongoose.Schema(
  {
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true, required: true },
    keyword: { type: String, required: true, trim: true },
    keywordLower: { type: String, required: true, index: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    source: { type: String, default: "custom" }
  },
  { timestamps: true }
);

// Unique per child (case-insensitive via keywordLower)
KeywordEntrySchema.index({ childId: 1, keywordLower: 1 }, { unique: true });

export default mongoose.model("KeywordEntry", KeywordEntrySchema);
