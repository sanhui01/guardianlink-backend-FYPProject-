// src/models/AppTempUnblock.js
import mongoose from "mongoose";

const AppTempUnblockSchema = new mongoose.Schema(
  {
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    packageName: { type: String, required: true, trim: true, index: true },
    until: { type: Date, required: true, index: true }, // when the temp unblock expires
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

// Active temp-unblock uniqueness (per child/pkg)
AppTempUnblockSchema.index({ childId: 1, packageName: 1 }, { unique: true, name: "uniq_child_pkg_unblock" });

const AppTempUnblock = mongoose.model("AppTempUnblock", AppTempUnblockSchema, "app_temp_unblocks");
export default AppTempUnblock;
