// src/models/HistoryEntry.js
import mongoose from "mongoose";

const { Schema, model } = mongoose;

const historyEntrySchema = new Schema({
    childId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    url: {
      type: String,
      required: true,
      trim: true,
    },
    host: {
      type: String,
      required: true,
      trim: true,
    },
    path: {
      type: String,
      required: true,
      trim: true,
    },
    title: {
      type: String,
      default: "",
      trim: true,
    },
    appPackage: {
      type: String,
      default: "",
      trim: true,
    },
    sourceType: {
      type: String,
      enum: ["browser", "search", "other"],
      default: "browser",
    },
    isUnsafe: {
      type: Boolean,
      default: false,
    },
    reason: {
      type: String,
      default: "",
      trim: true,
    },
    visitedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {timestamps: false,}
);

// Fast queries like "history for child X on date"
historyEntrySchema.index({ childId: 1, visitedAt: -1 });

const HistoryEntry = model("HistoryEntry", historyEntrySchema, "historyEntries");

export default HistoryEntry;
