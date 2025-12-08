// src/models/TimeLimitSetting.js
import mongoose from "mongoose";

const schema = new mongoose.Schema(
  {
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "users", index: true, required: true },
    // Daily screen time limit in MINUTES
    dailyMinutes: { type: Number, default: 0 }, // 0 = Unlimited
    // extra minutes from rewards, for *today only*
    bonusMinutes: { type: Number, default: 0 },
    // when the bonus expires (usually end of day)
    bonusExpiresAt: { type: Date },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "users" },
  },
  { timestamps: true }
);

schema.index({ childId: 1 }, { unique: true });

export default mongoose.model("TimeLimitSetting", schema, "time_limit_settings");
