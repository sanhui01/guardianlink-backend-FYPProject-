// src/routes/chat.js
import { Router } from "express";
import mongoose from "mongoose";
import fs from "fs";
import path from "path";
import multer from "multer";
import crypto from "crypto";

import User from "../models/User.js";
import ChatMessage from "../models/ChatMessage.js";
import PushToken from "../models/PushToken.js";
import { sendPushToTokens } from "../utils/push.js";
import { requireAuth } from "../middleware/authz.js";

import {
  encryptVoiceBuffer,
  decryptVoiceBuffer,
} from "../utils/fileCrypto.js";

const router = Router();

const CHAT_AES_KEY = Buffer.from(
  process.env.CHAT_AES_KEY ||
  "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
  "hex"
);

// Encrypts a UTF-8 string -> { ciphertextB64, nonceB64 }
function encryptText(plain) {
  // If input is null, return empty encrypt data
  if (plain == null) {
    return { ciphertextB64: "", nonceB64: "" };
  }
  const iv = crypto.randomBytes(12); // Generate 12-byte IV (AES-GCM is 12 bytes)
  // Create a AES-256-GCM cipher instances in:
  //Algorithm: aes-256-gcm, key: CHAT_AES_KEY and iv
  const cipher = crypto.createCipheriv("aes-256-gcm", CHAT_AES_KEY, iv);
  // Encrypt the plaintext
  const enc = Buffer.concat([
    cipher.update(String(plain), "utf8"), // Convert plaintext to UTF-8 bytes
    cipher.final(),
  ]);
  // Retrieve the GCM authentication tag
  const tag = cipher.getAuthTag();
  // Combine encrypted bytes and authentication tag
  const combined = Buffer.concat([enc, tag]); 
  return {
    ciphertextB64: combined.toString("base64"),
    nonceB64: iv.toString("base64"),
  };
}

// Decrypts base64 in cipher + tag + base64(iv) -> UTF-8 string or null
function decryptText(cipherB64, nonceB64) {
  try {
    if (!cipherB64 || !nonceB64) return null;
    const full = Buffer.from(cipherB64, "base64");
    if (full.length < 16) return null;

    const data = full.slice(0, full.length - 16);
    const tag = full.slice(full.length - 16);
    const iv = Buffer.from(nonceB64, "base64");

    const decipher = crypto.createDecipheriv("aes-256-gcm", CHAT_AES_KEY, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(data), decipher.final()]);
    return dec.toString("utf8");
  } catch {
    return null;
  }
}


// Multer setup for voice uploads 
const uploadRoot = path.resolve("uploads/voice");
fs.mkdirSync(uploadRoot, { recursive: true });

// Storage memory to store encrypted bytes to disk
const storage = multer.memoryStorage();
const upload = multer({ storage });

// small helper to check parent<->child in same family
async function validatePair(me, otherUserId) {
  if (!otherUserId || !mongoose.isValidObjectId(otherUserId)) {
    return { error: "toUserId is required" };
  }
  // Load the receiver from database
  const receiver = await User.findById(otherUserId).select("_id role familyId");
  if (!receiver) {
    return { error: "Receiver not found" };
  }
  // Check if both users belong to the same family
  if (String(receiver.familyId) !== String(me.familyId)) {
    return { error: "Users must be in the same family", status: 403 };
  }
  // Check valid parent-child pair
  // Allowed only if one is Parent and the other is Child
  const okPair =
    (me.role === "Parent" && receiver.role === "Child") ||
    (me.role === "Child" && receiver.role === "Parent");
  if (!okPair) {
    return {
      error: "Chat allowed only between a Parent and a Child",
      status: 403,
    };
  }
  // If everything is valid, return the receiver
  return { receiver };
}

// small helper for push the message
async function pushNewMessage(me, receiver, messageId) {
  const tokens = await PushToken.find({
    userId: receiver._id,
  }).distinct("fcmToken");

  if (!tokens.length) return;

  const title =
    me.role === "Parent"
      ? "New secure message from Parent"
      : "New secure message from Child";

  const body = "You have a new secure message.";

  await sendPushToTokens(
    tokens,
    { title, body },
    {
      type: "chat-message",
      fromUserId: String(me._id),
      toUserId: String(receiver._id),
      messageId: String(messageId),
    }
  );
}

// POST /chat/send
router.post("/send", requireAuth, async (req, res) => {
  try {
    const { // Destructure expected fields from request body
      toUserId,keyId,ciphertext,nonce,type,mediaUrl,mediaDurationMs,
    } = req.body || {};
    // Basic validation on 3 fields are mandatory for secure chat
    if (!keyId || !ciphertext || !nonce) {
      return res
        .status(400)
        .json({ message: "keyId, ciphertext, nonce are required" });
    }
    const me = req.user;  // Current authenticated user (sender)
    // Validate that the receiver is a valid chat partner
    const { error, status, receiver } = await validatePair(me, toUserId);
    if (error) {
      return res.status(status || 400).json({ message: error });
    }
    // Normalize message type: only "text" or "audio"
    const msgType = type === "audio" ? "audio" : "text";
    // Treat the incoming "ciphertext" field from client as PLAINTEXT.
    const plainFromClient = String(ciphertext);
    // Encrypt the plaintext using AES-256-GCM.
    const { ciphertextB64, nonceB64 } = encryptText(plainFromClient);
    const doc = await ChatMessage.create({
      familyId: me.familyId,
      senderId: me._id,
      receiverId: receiver._id,
      roleFrom: me.role,
      roleTo: receiver.role,
      type: msgType,
      keyId,
      ciphertext: ciphertextB64,
      nonce: nonceB64, // Nonce used for AES-GCM (Base64)
      mediaUrl: msgType === "audio" ? mediaUrl : undefined,
      mediaDurationMs:
        msgType === "audio" && mediaDurationMs != null
          ? Number(mediaDurationMs) // Store duration in ms for audio messages
          : undefined,
    });
    // Notify receiver via push notification (FCM) about the new message
    await pushNewMessage(me, receiver, doc._id);
    res.status(201).json({
      ok: true,
      messageId: doc._id,
      sentAt: doc.sentAt,
      mediaUrl: doc.mediaUrl || null,
    });
  } catch (err) {
    console.error("❌ /chat/send error:", err);
    res.status(500).json({ message: "Failed to send message" });
  }
});


// voice upload endpoint
router.post(
  "/send-voice",
  requireAuth, // User must be logged in
  upload.single("file"), // Multer middleware expecting "file" field
  async (req, res) => {
    try {
      const { toUserId, keyId, ciphertext, nonce, mediaDurationMs } =
        req.body || {};
      // Must include the audio file blob  
      if (!req.file) {
        return res.status(400).json({ message: "Audio file missing" });
      }
      // Must include secure-chat metadata fields
      if (!keyId || !ciphertext || !nonce) {
        return res
          .status(400)
          .json({ message: "keyId, ciphertext, nonce are required" });
      }
      const me = req.user;
      // Validate parent<->child pairing and same family
      const { error, status, receiver } = await validatePair(me, toUserId);
      if (error) {
        // Using memoryStorage, so no temp file cleanup needed
        return res.status(status || 400).json({ message: error });
      }
      // Determine output file extension
      const ext =
        path.extname(req.file.originalname || ".m4a") || ".m4a";
      // Generate random filename: voice_<timestamp>_<random>
      const base = `voice_${Date.now()}_${Math.random()
        .toString(36)
        .slice(2, 8)}`;
      const filename = `${base}${ext}`;
      // Absolute filesystem path for saving encrypted audio
      const absPath = path.join(uploadRoot, filename);
      // Encrypt the raw audio bytes in memory
      const { iv, authTag, ciphertext: encBuf } = encryptVoiceBuffer(
        req.file.buffer
      );
      // Combine iv + authTag + encrypted bytes to produce final encrypted payload
      const payload = Buffer.concat([iv, authTag, encBuf]);
      // Write encrypted voice file to disk
      await fs.promises.writeFile(absPath, payload);
      // URL path that Android clients will use to fetch this encrypted media
      const relPath = `/chat/media/${filename}`;
      // We don't need actual text here, but to keep DB consistent,
      // encrypt a small label like "voice-message".
      const { ciphertextB64, nonceB64 } = encryptText("voice-message");
      const doc = await ChatMessage.create({
        familyId: me.familyId,
        senderId: me._id,
        receiverId: receiver._id,
        roleFrom: me.role,
        roleTo: receiver.role,
        type: "audio",
        keyId,
        ciphertext: ciphertextB64,
        nonce: nonceB64,
        mediaUrl: relPath,
        mediaDurationMs:
          mediaDurationMs != null ? Number(mediaDurationMs) : undefined,
      });

      await pushNewMessage(me, receiver, doc._id);

      return res.status(201).json({
        ok: true,
        messageId: doc._id,
        sentAt: doc.sentAt,
        mediaUrl: relPath,
      });
    } catch (err) {
      console.error("❌ /chat/send-voice error:", err);
      return res.status(500).json({ message: "Failed to send voice message" });
    }
  }
);

// GET /chat/media/:filename (decrypt + stream audio)
router.get("/media/:filename", async (req, res) => {
  try {
    // Extract the requested filename from URL parameters
    const filename = req.params.filename || "";
    // Basic validation to prevent directory traversal attacks
    if (
      !filename ||
      filename.includes("..") ||
      filename.includes("/") ||
      filename.includes("\\")
    ) {
      return res.status(400).json({ message: "Invalid filename" });
    }
    const absPath = path.join(uploadRoot, filename);
    // Attempt to read file metadata
    let stat;
    try {
      stat = await fs.promises.stat(absPath);
    } catch {
      console.error("[MEDIA] file not found:", absPath);
      return res.status(404).json({ message: "File not found" });
    }
    // If path exists but is not a regular file will reject
    if (!stat.isFile()) {
      console.error("[MEDIA] not a file:", absPath);
      return res.status(404).json({ message: "File not found" });
    }

    const encData = await fs.promises.readFile(absPath);
    console.log(`[MEDIA] serving ${filename}, size=${encData.length} bytes`);

    let audioBuffer;
    // Check if file is too small to contain IV + AuthTag:
    // - IV: 12 bytes
    // - AuthTag: 16 bytes
    // → total minimum = 28 bytes
    if (encData.length < 12 + 16) {
      console.log("[MEDIA] legacy/plain voice file detected");
      audioBuffer = encData;
    } else {
      const iv = encData.slice(0, 12);
      const authTag = encData.slice(12, 28);
      const ciphertext = encData.slice(28);

      try {
        // Decrypt voice buffer → returns raw audio bytes
        audioBuffer = decryptVoiceBuffer(iv, authTag, ciphertext);
        console.log(
          "[MEDIA] decrypt ok, decrypted size=",
          audioBuffer.length
        );
      } catch (e) {
        console.error("[MEDIA] decrypt FAILED:", e);
        return res
          .status(500)
          .json({ message: "Failed to decrypt voice media" });
      }
    }
    // Set proper audio file headers so Android can play the audio buffer
    res.setHeader("Content-Type", "audio/mp4");
    res.setHeader("Content-Length", audioBuffer.length);
    return res.end(audioBuffer); // Stream decrypted audio back to the client
  } catch (err) {
    console.error("❌ /chat/media error:", err);
    return res.status(500).json({ message: "Failed to load voice media" });
  }
});




/**
 * GET /chat/messages?withUserId=...&limit=50&before=ISO_DATE
 * Returns encrypted messages between current user and withUserId
 * (Parent <-> Child only, same family).
 */
router.get("/messages", requireAuth, async (req, res) => {
  try {
    const { withUserId, limit, before } = req.query;
    if (!withUserId || !mongoose.isValidObjectId(withUserId)) {
      return res.status(400).json({ message: "withUserId is required" });
    }
    const me = req.user;
    const other = await User.findById(withUserId).select("_id role familyId");
    if (!other) {
      return res.status(404).json({ message: "User not found" });
    }
    // Same family only
    if (String(other.familyId) !== String(me.familyId)) {
      return res
        .status(403)
        .json({ message: "Users must be in the same family" });
    }
    // Only Parent <-> Child chat allowed
    const okPair =
      (me.role === "Parent" && other.role === "Child") ||
      (me.role === "Child" && other.role === "Parent");
    if (!okPair) {
      return res
        .status(403)
        .json({ message: "Chat allowed only between a Parent and a Child" });
    }

    // Safely clamp limit between 1 and 200 (default 50)
    const lim = Math.max(1, Math.min(Number(limit) || 50, 200));
    // Base query: messages in same family between me and the other user
    const match = {
      familyId: me.familyId,
      $or: [
        { senderId: me._id, receiverId: other._id },
        { senderId: other._id, receiverId: me._id },
      ],
    };
    // Only messages sent before a certain date 
    if (before) {
      const dt = new Date(before);
      if (!isNaN(dt.getTime())) {
        match.sentAt = { $lt: dt };
      }
    }
    // Fetch messages from MongoDB
    const rows = await ChatMessage.find(match)
      .sort({ sentAt: 1 }) // oldest -> newest
      .limit(lim)
      .lean();

    // Map messages and add a plaintext field for client
    const mapped = rows.map((doc) => {
      const out = { ...doc };
      if (doc.type === "text") {
         // Decrypt text messages for displa
        const plain = decryptText(doc.ciphertext, doc.nonce);
        if (plain != null) out.plaintext = plain;
      } else if (doc.type === "audio") {
        out.plaintext = "[Voice message]";
      }
      return out;
    });

    res.json(mapped);
  } catch (err) {
    console.error("❌ /chat/messages error:", err);
    res.status(500).json({ message: "Failed to load messages" });
  }
});


/**
 * POST /chat/read
 * Body: { withUserId: "...", before?: ISO_DATE }
 */
router.post("/read", requireAuth, async (req, res) => {
  try {
    const { withUserId, before } = req.body || {};

    if (!withUserId || !mongoose.isValidObjectId(withUserId)) {
      return res.status(400).json({ message: "withUserId is required" });
    }

    const me = req.user;
    const other = await User.findById(withUserId).select("_id familyId role");
    if (!other) {
      return res.status(404).json({ message: "User not found" });
    }

    if (String(other.familyId) !== String(me.familyId)) {
      return res
        .status(403)
        .json({ message: "Users must be in the same family" });
    }

    const match = {
      familyId: me.familyId,
      senderId: other._id,
      receiverId: me._id,
      readAt: null,
    };

    if (before) {
      const dt = new Date(before);
      if (!isNaN(dt.getTime())) {
        match.sentAt = { $lte: dt };
      }
    }

    const result = await ChatMessage.updateMany(match, {
      $set: { readAt: new Date() },
    });

    res.json({ ok: true, updated: result.modifiedCount });
  } catch (err) {
    console.error("❌ /chat/read error:", err);
    res.status(500).json({ message: "Failed to mark messages as read" });
  }
});

export default router;
