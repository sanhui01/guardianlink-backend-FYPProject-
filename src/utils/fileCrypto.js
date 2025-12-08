// src/utils/fileCrypto.js
import crypto from "crypto";

/**
 * Voice/media AES-256-GCM key.
 * Must be 32 bytes (64 hex chars). If VOICE_AES_KEY is missing or invalid,
 * we fall back to a hard-coded dev key.
 */
function getVoiceKey() {
  const hex = process.env.VOICE_AES_KEY ||
    "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";

  const buf = Buffer.from(hex, "hex");
  if (buf.length !== 32) {
    console.warn(
      "[fileCrypto] VOICE_AES_KEY is missing or invalid length; using fallback dev key."
    );
    return Buffer.from(
      "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
      "hex"
    );
  }
  return buf;
}

const VOICE_KEY = getVoiceKey();

/**
 * Encrypts a Buffer with AES-256-GCM (voice/media).
 * Returnsiv, authTag, ciphertext as Buffers.
 */
export function encryptVoiceBuffer(plainBuffer) {
  // If the input is NOT already a Buffer, convert it into a Buffer.
  if (!Buffer.isBuffer(plainBuffer)) {
    plainBuffer = Buffer.from(plainBuffer);
  }
  // Generate a random 12-byte IV (nonce).
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", VOICE_KEY, iv);
  // Encrypt the input buffer.
  const ciphertext = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  // Retrieve the 16-byte GCM authentication tag.
  // This tag is required for decryption and ensures the ciphertext was not tampered with.
  const authTag = cipher.getAuthTag();
  return { iv, authTag, ciphertext };
}

/**
 * Decrypts an AES-256-GCM payload (voice/media).
 * iv, authTag, ciphertext are Buffers.
 * Returns a Buffer with the decrypted data.
 */
export function decryptVoiceBuffer(iv, authTag, ciphertext) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", VOICE_KEY, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted;
}
