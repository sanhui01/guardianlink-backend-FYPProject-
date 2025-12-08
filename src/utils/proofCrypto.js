// src/utils/proofCrypto.js
import crypto from "crypto";
import fs from "fs";
import path from "path";

const IV_LENGTH = 12; // 96 bits for GCM
const DEFAULT_DIR = path.join(process.cwd(), "uploads", "proofs");

// Directory for encrypted proof photos
export const PROOF_DIR =
  process.env.PROOF_UPLOAD_DIR && process.env.PROOF_UPLOAD_DIR.trim().length
    ? process.env.PROOF_UPLOAD_DIR
    : DEFAULT_DIR;

if (!fs.existsSync(PROOF_DIR)) {
  fs.mkdirSync(PROOF_DIR, { recursive: true });
  console.log("📁 Created proof-photo directory:", PROOF_DIR);
}

// Encryption key (32 bytes = AES-256)
let KEY;
const keyB64 = process.env.PROOF_PHOTO_KEY;

if (keyB64) {
  try {
    const buf = Buffer.from(keyB64, "base64");
    if (buf.length !== 32) {
      console.warn(
        "⚠ PROOF_PHOTO_KEY must be 32 bytes (base64 of 256-bit key). Using random dev key instead – photos will BREAK across restarts."
      );
      KEY = crypto.randomBytes(32);
    } else {
      KEY = buf;
    }
  } catch (e) {
    console.warn(
      "⚠ Failed to parse PROOF_PHOTO_KEY. Using random dev key instead – photos will BREAK across restarts.",
      e.message
    );
    KEY = crypto.randomBytes(32);
  }
} else {
  console.warn(
    "⚠ PROOF_PHOTO_KEY not set. Using random dev key – encrypted photos will NOT survive server restarts. Set a base64 32-byte key in production."
  );
  KEY = crypto.randomBytes(32);
}

export function proofPathForTask(taskId) {
  return path.join(PROOF_DIR, `${taskId}.enc`);
}

// Encrypt buffer and save to disk for given taskId
export function encryptAndSaveProof(taskId, buffer) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);

  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();

  // layout: [iv | tag | ciphertext]
  const out = Buffer.concat([iv, tag, encrypted]);
  const filePath = proofPathForTask(taskId);

  fs.writeFileSync(filePath, out);
  return filePath;
}

// Load encrypted file for taskId and decrypt to raw image bytes
export function loadAndDecryptProof(taskId) {
  const filePath = proofPathForTask(taskId);
  if (!fs.existsSync(filePath)) {
    const e = new Error("Proof photo not found");
    e.code = "ENOENT";
    throw e;
  }

  const buf = fs.readFileSync(filePath);
  if (buf.length < IV_LENGTH + 16 + 1) {
    const e = new Error("Corrupted proof photo");
    e.code = "EBADFILE";
    throw e;
  }

  const iv = buf.slice(0, IV_LENGTH);
  const tag = buf.slice(IV_LENGTH, IV_LENGTH + 16);
  const data = buf.slice(IV_LENGTH + 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(data), decipher.final()]);
}
