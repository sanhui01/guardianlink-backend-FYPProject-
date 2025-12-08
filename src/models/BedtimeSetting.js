import mongoose from "mongoose";

const BedtimeSettingSchema = new mongoose.Schema(
  {
    childId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
      required: true,
      unique: true,
    },
    start: {
      // "HH:mm" 24h, e.g. "22:00"
      type: String,
      required: true,
      match: /^[0-2]\d:[0-5]\d$/,
    },
    end: {
      // "HH:mm" 24h, can be less than start (crosses midnight)
      type: String,
      required: true,
      match: /^[0-2]\d:[0-5]\d$/,
    },
    timezone: {
      type: String,
      default: "Asia/Kuala_Lumpur",
      enum: ["Asia/Kuala_Lumpur"], // Fix the timezone only Asia/Kuala_Lumpur
    },
    enabled: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

export default mongoose.model("BedtimeSetting", BedtimeSettingSchema);
