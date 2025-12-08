// src/models/BlockEntry.js
import mongoose from "mongoose";
import crypto from "crypto";

const BlockEntrySchema = new mongoose.Schema(
  {
    childId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    // saved as provided by parent for UI
    urlOriginal: { type: String, required: true },
    // normalized representation used for enforcement & uniqueness
    urlNormalized: { type: String, required: true },
    host: { type: String, required: true },
    path: { type: String, required: true }, // "/" allowed
    urlHash: { type: String, required: true }, // sha256 of urlNormalized
    source: { type: String, enum: ["custom", "feed"], default: "custom" },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // parent who added
  },
  { timestamps: true }
);

// unique per-child
BlockEntrySchema.index({ childId: 1, urlHash: 1 }, { unique: true });

/** Utility: normalize an incoming URL. Throws if invalid. */
export function normalizeUrl(input) {
  if (typeof input !== "string") throw new Error("URL must be string");
  const trimmed = input.trim();

  // Add scheme if user typed "example.com"
  const withScheme = /^(https?:)?\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let url;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error("Invalid URL");
  }
  if (!/^https?$/i.test(url.protocol.replace(":", ""))) {
    throw new Error("Only http/https URLs are allowed");
  }

  // canonicalize
  url.hash = ""; // drop fragments
  // drop default port
  if ((url.protocol === "http:" && url.port === "80") || (url.protocol === "https:" && url.port === "443")) {
    url.port = "";
  }

  const host = url.hostname.toLowerCase();
  // normalize path: keep leading "/", drop trailing "/" unless root
  let path = url.pathname || "/";
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);

  const normalized = `${url.protocol}//${host}${url.port ? ":" + url.port : ""}${path}`;
  const urlHash = crypto.createHash("sha256").update(normalized).digest("hex");
  return { normalized, host, path, urlHash };
}

const BlockEntry = mongoose.model("BlockEntry", BlockEntrySchema, "block_entries");
export default BlockEntry;
