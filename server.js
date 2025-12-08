// server.js 
import "dotenv/config.js";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import morgan from "morgan";
import path from "path";

import authRoutes from "./src/routes/auth.js";
import userRoutes from "./src/routes/users.js"; 
import adminRoutes from "./src/routes/admin.js";

import blocklistRoutes from "./src/routes/blocklist.js";
import policyRoutes from "./src/routes/policy.js";
import activityRoutes from "./src/routes/activity.js";

import appBlocksRoutes from "./src/routes/appBlocks.js";
import appInventoryRoutes from "./src/routes/appInventory.js";

import keywordRoutes from "./src/routes/keywords.js";

import screenTimeRoutes from "./src/routes/screenTimeRoutes.js";

import bedtimeRoutes from "./src/routes/bedtime.js";

import pushTokensRoutes from "./src/routes/pushTokens.js";

import chatRoutes from "./src/routes/chat.js";

import { generalLimiterWithSkip } from "./src/middleware/rateLimiters.js";
import { verifyMailer } from "./src/utils/mailer.js";
import diaryRoutes from "./src/routes/diary.js";
import rewardsRoutes from "./src/routes/rewards.js";
import remoteRoutes from "./src/routes/remote.js";
import securityRoutes from './src/routes/security.js';

const app = express();

// --- Core middleware ---
app.use(cors());
app.use(express.json());
app.use(morgan("tiny"));
app.use(generalLimiterWithSkip);

// --- Health first (no auth/limits confusion) ---
app.get("/health", (_req, res) => res.json({ ok: true }));

// --- Routes (mount order doesn’t matter for different base paths) ---
app.use("/auth", authRoutes); // auth
app.use("/users", userRoutes); // legacy/user utilities
app.use("/admin", adminRoutes); // family admin
app.use("/diary", diaryRoutes);
app.use("/rewards", rewardsRoutes);
app.use("/remote", remoteRoutes);

app.use("/blocklist", blocklistRoutes);
app.use("/policy", policyRoutes);
app.use("/activity", activityRoutes);
app.use('/security', securityRoutes);

app.use("/apps", appBlocksRoutes);
app.use("/inventory", appInventoryRoutes);

app.use("/keywords", keywordRoutes);

app.use("/api/screen-time", screenTimeRoutes);

app.use("/api/bedtime", bedtimeRoutes);

app.use("/push", pushTokensRoutes);

app.use("/chat", chatRoutes);


// --- 404 + error fallbacks (safe, quiet defaults) ---
app.use((_req, res) => res.status(404).json({ message: "Not found" }));
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ message: "Something went wrong" });
});

// --- SMTP check (non-blocking) ---
verifyMailer().catch((err) => {
  console.warn("❌ SMTP verify failed:", err?.message);
});

async function start() {
  const uri = process.env.MONGODB_URI;
  await mongoose.connect(uri, {
    dbName: process.env.MONGODB_DB || "GuardianLink",
    serverSelectionTimeoutMS: 10_000,
    retryWrites: true,
    tls: true,
  });
  console.log("✅ MongoDB connected:", mongoose.connection.name);

  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log(`✅ API running on :${port}`));
}

start().catch((e) => {
  console.error("❌ Fatal start error:", e);
  process.exit(1);
});
