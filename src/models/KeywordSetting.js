// src/models/KeywordSetting.js
import mongoose from "mongoose";

const KeywordSettingSchema = new mongoose.Schema(
  {
    childId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true,
      index: true,
    },
    alertsEnabled: { type: Boolean, default: false },   // for FCM alerts
    filterEnabled: { type: Boolean, default: true },    // keep for future
  },
  { timestamps: true }
);

export default mongoose.model(
  "KeywordSetting",
  KeywordSettingSchema,
  "keywordsettings"
);
