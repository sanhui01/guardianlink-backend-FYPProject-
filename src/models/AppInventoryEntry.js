// src/models/AppInventoryEntry.js
import mongoose from "mongoose";

const AppInventoryEntrySchema = new mongoose.Schema(
  {
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    packageName: { type: String, required: true, trim: true },
    appLabel: { type: String, default: "", trim: true }, // human readable name (e.g., "YouTube")
    versionName: { type: String, default: "" },
    versionCode: { type: String, default: "" },          // keep string for safety across SDKs
    systemApp: { type: Boolean, default: false },
    lastSeenAt: { type: Date, default: Date.now, index: true },
  },
  { timestamps: true }
);

// one row per (child, package)
AppInventoryEntrySchema.index({ childId: 1, packageName: 1 }, { unique: true, name: "uniq_child_pkg_inventory" });

const AppInventoryEntry = mongoose.model("AppInventoryEntry", AppInventoryEntrySchema, "app_inventory_entries");
export default AppInventoryEntry;
