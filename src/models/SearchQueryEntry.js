import mongoose from "mongoose";

const { Schema, model } = mongoose;

const searchQuerySchema = new Schema(
  {
    childId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    query: {
      type: String,
      required: true,
      trim: true,
    },
    engine: {
      type: String,
      enum: ["google", "bing", "youtube", "unknown"],
      default: "unknown",
    },
    url: {
      type: String,
      default: "",
    },
    appPackage: {
      type: String,
      default: "",
    },
    sourceType: {
      type: String,
      default: "search",
    },
    isUnsafe: {
      type: Boolean,
      default: false,
    },
    reason: {
      type: String,
      default: "",
    },
    searchedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: false,
  }
);

searchQuerySchema.index({ childId: 1, searchedAt: -1 });

export default model("SearchQueryEntry", searchQuerySchema, "searchQueries");
