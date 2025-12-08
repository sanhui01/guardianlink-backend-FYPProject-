// src/models/RemoteSession.js
import mongoose from "mongoose";

// src/models/RemoteSession.js
const RemoteCommandSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: [
        "LOCK",
        "UNLOCK",
        "PAUSE_NET",
        "RESUME_NET",
        "GRANT_CONTROL",
        "REVOKE_CONTROL",
        "FORCE_LOCK",
        "CHILD_ACCEPT",
      ],
      required: true,
    },
    payload: { type: Object, default: {} },
    at: { type: Date, default: Date.now },
  },
  { _id: false }
);


const RemoteSessionSchema = new mongoose.Schema(
  {
    familyId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
      required: true,
    },
    parentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
      required: true,
    },
    childId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
      required: true,
    },

    controlGranted: { type: Boolean, default: false },

    startedAt: { type: Date, default: Date.now },
    endedAt: { type: Date, default: null },
    commands: {
      type: [RemoteCommandSchema],
      default: [],
    },
  },
  {
    timestamps: true, // createdAt/updatedAt
  }
);

const RemoteSession = mongoose.model("RemoteSession", RemoteSessionSchema);
export default RemoteSession;
