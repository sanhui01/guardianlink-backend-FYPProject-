// src/models/AppBlockEntry.js
import mongoose from "mongoose";

const AppBlockEntrySchema = new mongoose.Schema(
  {
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    packageName: { type: String, required: true, trim: true },
    source: { type: String, enum: ["custom", "admin"], default: "custom" },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

// Each package can appear once per child
AppBlockEntrySchema.index({ childId: 1, packageName: 1 }, { unique: true, name: "uniq_child_pkg" });

const AppBlockEntry = mongoose.model("AppBlockEntry", AppBlockEntrySchema, "app_block_entries");
export default AppBlockEntry;
