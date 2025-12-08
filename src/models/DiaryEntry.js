import mongoose from "mongoose";

const DiaryEntrySchema = new mongoose.Schema(
  {
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    title: { type: String, trim: true, maxlength: 120, default: "" },
    content: { type: String, required: true, maxlength: 5000 },
    mood: {
      type: String,
      enum: ["happy","okay","sad","angry","anxious","proud","none"],
      default: "none"
    },
    isSharedWithParent: { type: Boolean, default: false, index: true },
    sharedAt: { type: Date },

    tags: [{ type: String, trim: true }],
    wordCount: { type: Number, default: 0 },
    summary: { type: String, default: "" }
  },
  { timestamps: true }
);

DiaryEntrySchema.index({ isSharedWithParent: 1, childId: 1, sharedAt: -1 });
DiaryEntrySchema.index({ childId: 1, createdAt: -1 });

export default mongoose.model("DiaryEntry", DiaryEntrySchema);
