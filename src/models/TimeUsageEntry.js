// src/models/TimeUsageEntry.js
import mongoose from "mongoose";

/** one document per child per day (UTC yyyy-mm-dd) */
const schema = new mongoose.Schema(
  {
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "users", index: true, required: true },
    date: { type: String, index: true, required: true }, // Format: "2025-11-12"
    totalSeconds: { type: Number, default: 0 },          // sum usage
    byApp: { type: Map, of: Number, default: {} },       // breakdown: { "com.app": seconds }
    lastTickAt: { type: Date, default: null },
  },
  { timestamps: true }
);

schema.index({ childId: 1, date: 1 }, { unique: true });

export default mongoose.model("TimeUsageEntry", schema, "time_usage_entries");
