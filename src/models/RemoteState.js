// src/models/RemoteState.js
import mongoose from "mongoose";

const { Schema, model } = mongoose;

const RemoteStateSchema = new Schema(
  {
    childId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      index: true,
      unique: true, // one row per child
      required: true,
    },
    locked: { type: Boolean, default: false },        // full lock
    pauseNet: { type: Boolean, default: false },      // pause risky apps
    forceLockUntil: { type: Date, default: null },    // optional timer
    controlGranted: { type: Boolean, default: false },
  },
  {
    timestamps: true,
  }
);

const RemoteState = model("RemoteState", RemoteStateSchema);
export default RemoteState;
