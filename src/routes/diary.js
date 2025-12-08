// src/routes/diary.js
import { Router } from "express";
import rateLimit from "express-rate-limit";
import { body, param, validationResult } from "express-validator";
import DiaryEntry from "../models/DiaryEntry.js";
import { requireAuth } from "../middleware/authz.js";
import User from "../models/User.js";
import { sendPushToTokens } from "../utils/push.js";
import PushToken from "../models/PushToken.js";

// Reward ledger + dayjs for daily diary points
import RewardPointEntry from "../models/RewardPointEntry.js";
import dayjs from "dayjs";
import utc from "dayjs/plugin/utc.js";
import timezone from "dayjs/plugin/timezone.js";

dayjs.extend(utc);
dayjs.extend(timezone);
dayjs.tz.setDefault("Asia/Kuala_Lumpur");

// Tunable points per day for writing diary
const DIARY_DAILY_POINTS = 10;

// Local, gentle limiter (doesn't touch your global limiter)
const diaryLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

const r = Router();
r.use(diaryLimiter);

// --- helpers ---
function assertChild(req) {
  if (req.user.role !== "Child") {
    const e = new Error("Child role required");
    e.status = 403;
    throw e;
  }
}

function assertParent(req) {
  if (req.user.role !== "Parent") {
    const e = new Error("Parent role required");
    e.status = 403;
    throw e;
  }
}

/** return false when validation failed (and response is already sent) */
function handleValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ errors: errors.array() });
    return false;
  }
  return true;
}

function deriveTextMeta(content) {
  const safe = (content || "").toString();
  const trimmed = safe.trim();
  const wordCount = trimmed.length ? trimmed.split(/\s+/).length : 0;
  const summary = safe.slice(0, 150);
  return { wordCount, summary };
}

function countWords(text = "") {
  return text
    .trim()
    .split(/\s+/)
    .filter(Boolean).length;
}

// Mood weights & helpers for emotional risk scoring
const MOOD_WEIGHT = {
  happy: -1,
  proud: -1,
  okay: 0,
  sad: 2,
  anxious: 3,
  angry: 2,
  none: 0,
};

const NEGATIVE_MOODS = new Set(["sad", "angry", "anxious"]);
const POSITIVE_MOODS = new Set(["happy", "proud", "okay"]);

function moodWeight(mood) {
  return MOOD_WEIGHT[mood] ?? 0;
}


// Award diary points once per day per child
async function maybeAwardDiaryDailyPoints(user, entry) {
  try {
    if (!user?.familyId) return;

    const tz = "Asia/Kuala_Lumpur";
    const startOfToday = dayjs().tz(tz).startOf("day").toDate();

    const existing = await RewardPointEntry.findOne({
      childId: user._id,
      source: "diary",
      createdAt: { $gte: startOfToday },
    })
      .select("_id")
      .lean();

    if (existing) return;

    await RewardPointEntry.create({
      familyId: user.familyId,
      childId: user._id,
      source: "diary",
      delta: DIARY_DAILY_POINTS,
      description: "Daily diary entry",
    });

    console.log(
      `[DIARY] awarded ${DIARY_DAILY_POINTS} pts to child=${user._id} for entry=${entry._id}`
    );
  } catch (e) {
    console.error("diary reward points error:", e.message || e);
  }
}


// ---------------- CHILD: create ----------------
r.post(
  "/",
  requireAuth,
  body("content").isString().trim().isLength({ min: 1, max: 5000 }),
  body("title").optional().isString().trim().isLength({ max: 120 }),
  body("mood").optional().isIn(["happy", "okay", "sad", "angry", "anxious", "proud", "none"]),
  async (req, res) => {
    handleValidation(req, res); // may early-return (in practice inputs are valid)
    assertChild(req);

    const rawTitle = (req.body.title ?? "").trim();
    const rawContent = (req.body.content ?? "").trim();

    const tags = Array.isArray(req.body.tags)
      ? req.body.tags.map(t => String(t).trim()).filter(Boolean).slice(0, 5)
      : [];

    const entry = await DiaryEntry.create({
      childId: req.user._id,
      title: rawTitle,
      content: rawContent,
      mood: req.body.mood ?? "none",
      tags,
      wordCount: countWords(rawContent),
      summary: deriveTextMeta(rawContent).summary
    });

    // award daily diary points (first diary of the day)
    await maybeAwardDiaryDailyPoints(req.user, entry);

    res.status(201).json(entry);
  }
);


// ---------------- CHILD: list own entries ----------------
r.get("/mine", requireAuth, async (req, res) => {
  assertChild(req);
  const list = await DiaryEntry.find({ childId: req.user._id })
    .sort({ createdAt: -1 })
    .limit(200);
  res.json(list);
});

// ---------------- CHILD: update own entry ----------------
r.patch(
  "/:id",
  requireAuth,
  param("id").isMongoId(),
  body("title").optional().isString().trim().isLength({ max: 120 }),
  body("content").optional().isString().trim().isLength({ min: 1, max: 5000 }),
  body("mood").optional().isIn(["happy", "okay", "sad", "angry", "anxious", "proud", "none"]),
  async (req, res) => {
    if (!handleValidation(req, res)) return;
    assertChild(req);

    const update = {};

    if (typeof req.body.title === "string") {
      update.title = req.body.title.trim();
    }

    if (typeof req.body.content === "string") {
      const trimmed = req.body.content.trim();
      update.content = trimmed;
      const { wordCount, summary } = deriveTextMeta(trimmed);
      update.wordCount = wordCount;
      update.summary = summary;
    }

    if (typeof req.body.mood === "string") {
      update.mood = req.body.mood;
    }

    if (Array.isArray(req.body.tags)) {
      update.tags = req.body.tags
        .map(t => String(t).trim())
        .filter(Boolean)
        .slice(0, 5);
    }

    const entry = await DiaryEntry.findOneAndUpdate(
      { _id: req.params.id, childId: req.user._id },
      { $set: update },
      { new: true }
    );
    if (!entry) return res.status(404).json({ message: "Not found" });
    res.json(entry);
  }
);

// ---------------- CHILD: delete own entry ----------------
r.delete("/:id", requireAuth, param("id").isMongoId(), async (req, res) => {
  assertChild(req);
  const del = await DiaryEntry.findOneAndDelete({
    _id: req.params.id,
    childId: req.user._id,
  });
  if (!del) return res.status(404).json({ message: "Not found" });
  res.json({ ok: true });
});

// ---------------- CHILD: share / unshare ----------------
r.post("/:id/share", requireAuth, param("id").isMongoId(), async (req, res) => {
  assertChild(req);

  const entry = await DiaryEntry.findOneAndUpdate(
    { _id: req.params.id, childId: req.user._id },
    { $set: { isSharedWithParent: true, sharedAt: new Date() } },
    { new: true }
  );
  if (!entry) return res.status(404).json({ message: "Not found" });

  // 🔔 Push notification to all parent devices in the same family
  try {
    const child = await User.findById(req.user._id)
      .select("displayName familyId")
      .lean();

    if (!child?.familyId) {
      console.log("ℹ diary share: child has no familyId, skipping push");
    } else {
      const parentTokens = await PushToken.find({
        familyId: child.familyId,
        role: "Parent",
      })
        .select("fcmToken")
        .lean();

      const tokens = parentTokens.map(t => t.fcmToken).filter(Boolean);

      if (tokens.length) {
        const childName = child.displayName || "Your child";

        await sendPushToTokens(
          tokens,
          {
            title: `${childName} shared a diary entry`,
            body:
              entry.title?.trim() ||
              (entry.content || "").slice(0, 80) ||
              "New diary entry shared with you.",
          },
          {
            type: "diary_shared",
            childName,
            diaryId: String(entry._id),
          }
        );
      } else {
        console.log(
          "ℹ diary share: no parent push tokens found in family, skipping push"
        );
      }
    }
  } catch (e) {
    console.error("❌ diary share push error:", e.response?.data || e.message);
    // do not fail the API just because push failed
  }

  res.json(entry);
});

r.post("/:id/unshare", requireAuth, param("id").isMongoId(), async (req, res) => {
  assertChild(req);
  const entry = await DiaryEntry.findOneAndUpdate(
    { _id: req.params.id, childId: req.user._id },
    { $set: { isSharedWithParent: false, sharedAt: null } },
    { new: true }
  );
  if (!entry) return res.status(404).json({ message: "Not found" });
  res.json(entry);
});

// ---------------- PARENT: view shared from linked children ----------------
r.get("/shared", requireAuth, async (req, res) => {
  assertParent(req);

  const childIds = await User.find({ familyId: req.user.familyId, role: "Child" })
    .select("_id")
    .lean()
    .then(rows => rows.map(r => r._id));

  if (childIds.length === 0) return res.json([]);

  const list = await DiaryEntry.aggregate([
    { $match: { isSharedWithParent: true, childId: { $in: childIds } } },
    {
      $lookup: {
        from: "users",
        localField: "childId",
        foreignField: "_id",
        as: "child",
      },
    },
    { $unwind: "$child" },
    {
      $project: {
        childId: 1,
        title: 1,
        content: 1,
        mood: 1,
        isSharedWithParent: 1,
        sharedAt: 1,
        createdAt: 1,
        updatedAt: 1,
        childName: "$child.displayName",
      },
    },
    { $sort: { sharedAt: -1, createdAt: -1 } },
  ]);

  res.json(list);
});

// ---------------- PARENT: weekly insights ----------------
r.get("/insights", requireAuth, async (req, res) => {
  assertParent(req);

  const childDocs = await User.find({
    familyId: req.user.familyId,
    role: "Child",
  })
    .select("_id displayName")
    .lean();

  if (!childDocs.length) return res.json({ children: [] });

  const childIds = childDocs.map((c) => c._id);

  // last 7 days
  const since = new Date();
  since.setDate(since.getDate() - 7);

  const entries = await DiaryEntry.find({
    childId: { $in: childIds },
    createdAt: { $gte: since },
  })
    .select("childId mood wordCount createdAt")
    .lean();

  // Aggregate per child
  const aggMap = new Map();
  for (const c of childDocs) {
    aggMap.set(String(c._id), {
      childId: String(c._id),
      childName: c.displayName || "Child",
      entries: 0,
      totalWords: 0,
      moodCounts: {},        // { happy: x, sad: y, ... }
      positiveCount: 0,
      negativeCount: 0,
      daySet: new Set(),     // set of "YYYY-MM-DD" that have entries
    });
  }

  const tz = "Asia/Kuala_Lumpur";

  for (const e of entries) {
    const key = String(e.childId);
    const c = aggMap.get(key);
    if (!c) continue;

    c.entries++;
    c.totalWords += e.wordCount || 0;

    const mood = e.mood || "none";
    c.moodCounts[mood] = (c.moodCounts[mood] || 0) + 1;

    // classify mood as positive / negative
    if (["happy", "proud", "okay"].includes(mood)) {
      c.positiveCount++;
    }
    if (["sad", "angry", "anxious"].includes(mood)) {
      c.negativeCount++;
    }

    // track the day key for streak
    const dayKey = dayjs(e.createdAt).tz(tz).format("YYYY-MM-DD");
    c.daySet.add(dayKey);
  }

  const today = dayjs().tz("Asia/Kuala_Lumpur").startOf("day");

  function pickMost(moodCounts, list) {
    let best = null;
    let bestCount = 0;
    for (const m of list) {
      const cnt = moodCounts[m] || 0;
      if (cnt > bestCount) {
        best = m;
        bestCount = cnt;
      }
    }
    return best; // may be null
  }

  const children = Array.from(aggMap.values()).map((c) => {
    const avgWords = c.entries > 0 ? Math.round(c.totalWords / c.entries) : 0;

    // topMood (most frequent overall – keep for compatibility)
    const topMood =
      Object.entries(c.moodCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ||
      "none";

    // emotionalStreak: consecutive days from today backwards that have entries
    let emotionalStreak = 0;
    for (let i = 0; i < 7; i++) {
      const dKey = today.subtract(i, "day").format("YYYY-MM-DD");
      if (c.daySet.has(dKey)) emotionalStreak++;
      else break;
    }

    // emotionalStability based on how many different moods (ignoring "none")
    const moodKeys = Object.keys(c.moodCounts).filter(
      (m) => m !== "none" && c.moodCounts[m] > 0
    );

    let emotionalStability;
    if (c.entries === 0) {
      emotionalStability = "No data";
    } else if (moodKeys.length <= 1) {
      emotionalStability = "Stable";
    } else if (moodKeys.length <= 3) {
      emotionalStability = "Mixed";
    } else {
      emotionalStability = "Fluctuating";
    }

    const mostPositiveMood = pickMost(c.moodCounts, ["happy", "proud", "okay"]);
    const mostNegativeMood = pickMost(c.moodCounts, ["sad", "angry", "anxious"]);

    return {
      childId: c.childId,
      childName: c.childName,
      entries: c.entries,
      avgWords,
      topMood,

      emotionalStreak,
      emotionalStability,
      positiveCount: c.positiveCount,
      negativeCount: c.negativeCount,
      mostPositiveMood: mostPositiveMood || null,
      mostNegativeMood: mostNegativeMood || null,
    };
  });

  res.json({ children });
});



export default r;
