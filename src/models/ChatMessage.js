// src/models/ChatMessage.js
import mongoose from "mongoose";

const ChatMessageSchema = new mongoose.Schema(
  {
    // Family this conversation belongs to
    familyId: {
      type: mongoose.Schema.Types.ObjectId,
      index: true,
      required: true,
    },
    // Who sent / who receives
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
      required: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
      required: true,
    },
    // Helpful for debugging & UI (who is parent/child)
    roleFrom: {
      type: String,
      enum: ["Parent", "Child"],
      required: true,
    },
    roleTo: {
      type: String,
      enum: ["Parent", "Child"],
      required: true,
    },
    // "text" now; "audio" reserved for voice messages later
    type: {
      type: String,
      enum: ["text", "audio"],
      default: "text",
    },
    // E2E crypto info (frontend encrypts, backend never sees plaintext)
    keyId: {
      type: String,
      required: true,
    },
    ciphertext: {
      type: String,
      required: true,
    },
    nonce: {
      type: String,
      required: true,
    },
    // Voice message metadata (optional, for future)
    mediaUrl: { type: String },
    mediaDurationMs: { type: Number },

    // Delivery / read status (optional for now)
    delivered: { type: Boolean, default: false },
    readAt: { type: Date },
  },
  {
    // sentAt = createdAt
    timestamps: { createdAt: "sentAt", updatedAt: "updatedAt" },
  }
);

// Index for fast conversation queries
ChatMessageSchema.index(
  { familyId: 1, senderId: 1, receiverId: 1, sentAt: 1 },
  { name: "chat_by_family_and_pair" }
);

export default mongoose.model("ChatMessage", ChatMessageSchema, "chat_messages");
