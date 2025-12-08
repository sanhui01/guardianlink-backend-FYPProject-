// src/routes/screenTimeRoutes.js
import { Router } from "express";
import { query, body, validationResult } from "express-validator";
import { requireAuth } from "../middleware/authz.js";
import dayjs from "dayjs";
import utc from "dayjs/plugin/utc.js";
import timezone from "dayjs/plugin/timezone.js";
import TimeUsageEntry from "../models/TimeUsageEntry.js";
import TimeLimitSetting from "../models/TimeLimitSetting.js";

dayjs.extend(utc);
dayjs.extend(timezone);
dayjs.tz.setDefault("Asia/Kuala_Lumpur");

const r = Router();
const v = (req, res) => {
  const e = validationResult(req);
  if (!e.isEmpty()) return res.status(400).json({ errors: e.array() });
};

//  helpers 
const packKey = (pkg) => pkg.replace(/\./g, "_");
const unpackKey = (key) => key.replace(/_/g, ".");

// Helper: parent may ask for specific child; child may ask only for self
async function resolveChildIdOr403(req) {
  const requested = req.query.childId;

  // child will only always use own id, ignore provided childId
  if (req.user.role === "Child") {
    return String(req.user._id);
  }

  // Parent / Superuser
  const { default: User } = await import("../models/User.js");

  if (requested) {
    const kid = await User.findOne({ _id: requested, role: "Child" }).lean();
    if (!kid) {
      const e = new Error("Child not found");
      e.status = 404;
      throw e;
    }
    if (String(kid.familyId || "") !== String(req.user.familyId || "")) {
      const e = new Error("Child not in your family");
      e.status = 403;
      throw e;
    }
    return requested;
  }

  // Auto-pick first child in the family if none provided
  const firstChild = await User.findOne({
    familyId: req.user.familyId,
    role: "Child",
  })
    .select("_id")
    .lean();

  if (!firstChild) {
    const e = new Error("childId is required (no children in this family)");
    e.status = 400;
    throw e;
  }
  return String(firstChild._id);
}

function todayKey(tz = "Asia/Kuala_Lumpur") {
  return dayjs().tz(tz).format("YYYY-MM-DD");
}

// Combine base dailyMinutes with bonusMinutes if bonus is still valid
function computeEffectiveMinutes(limitDoc) {
  const base = limitDoc?.dailyMinutes ?? 0;

  let bonus = 0;
  const now = new Date();
  if (
    limitDoc &&
    typeof limitDoc.bonusMinutes === "number" &&
    limitDoc.bonusMinutes > 0 &&
    limitDoc.bonusExpiresAt &&
    limitDoc.bonusExpiresAt > now
  ) {
    bonus = limitDoc.bonusMinutes;
  }

  return {
    base,
    bonus,
    effective: base + bonus,
  };
}

r.get(
  "/limit",
  requireAuth,
  query("childId").optional().isMongoId(),
  async (req, res, next) => {
    try {
      v(req, res);
      const childId = await resolveChildIdOr403(req);
      const doc = await TimeLimitSetting.findOne({ childId }).lean();

      const { base, bonus, effective } = computeEffectiveMinutes(doc);
      res.json({
        childId,
        baseDailyMinutes: base,      // what parent set
        bonusMinutes: bonus,         // extra from rewards (today)
        effectiveDailyMinutes: effective, // base + bonus
        autoLock: !!doc?.autoLock,
        updatedAt: doc?.updatedAt ?? null,
      });
    } catch (e) {
      next(e);
    }
  }
);

r.post(
  "/limit",
  requireAuth,
  body("childId").isMongoId(),
  body("dailyMinutes").isInt({ min: 0, max: 24 * 60 }),
  body("autoLock").optional().isBoolean(),
  async (req, res, next) => {
    try {
      v(req, res);
      const { childId, dailyMinutes, autoLock = true } = req.body;

      if (req.user.role !== "Parent" && req.user.role !== "Superuser") {
        const e = new Error("Only parent can change limits");
        e.status = 403;
        throw e;
      }

      const doc = await TimeLimitSetting.findOneAndUpdate(
        { childId },
        { $set: { dailyMinutes, autoLock } },
        { upsert: true, new: true }
      ).lean();

      res.json({ ok: true, doc });
    } catch (e) {
      next(e);
    }
  }
);

// tick: child sends seconds & package 
// POST /api/screen-time/tick
r.post(
  "/tick",
  requireAuth,
  body("seconds").isInt({ min: 1, max: 3600 }),
  body("appPackage").optional().isString(),
  async (req, res, next) => {
    try {
      v(req, res);
      const childId = await resolveChildIdOr403(req);
      const { seconds, appPackage = "unknown.app" } = req.body;
      const dateKey = todayKey();
      const now = new Date();

      // Convert an app package name into a safe MongoDB key.
      const safeKey = packKey(appPackage);

      // Prepare the $inc (increment) values.
      // totalSeconds → adds to total daily usage
      // byApp.safeKey → adds usage for a specific app
      const inc = {
        totalSeconds: seconds,
        [`byApp.${safeKey}`]: seconds,
      };

      // Update or create (upsert) the child's TimeUsageEntry document for today
      const doc = await TimeUsageEntry.findOneAndUpdate(
        { childId, date: dateKey }, // Find entry for this child and today's date
        {
          $inc: inc,
          $setOnInsert: { childId, date: dateKey }, // Set ChildId and today's date if document does not exist
          $set: { lastTickAt: now }, // Update the latest timestamp of lastest tick
        },
        { upsert: true, new: true } // Create document if missing
      ).lean();

      console.log(
        `[TICK] childId=${childId} date=${dateKey} seconds=${seconds} app=${appPackage} (key=${safeKey})`
      );

      res.json({ ok: true, used: doc.totalSeconds ?? 0 });
    } catch (e) {
      next(e);
    }
  }
);


// today: single day summary 
// GET /api/screen-time/today
// GET /api/screen-time/today
r.get(
  "/today",
  requireAuth,
  query("childId").optional().isMongoId(),
  async (req, res, next) => {
    try {
      v(req, res);
      const childId = await resolveChildIdOr403(req);
      const dateKey = todayKey();

      const doc = await TimeUsageEntry.findOne({ childId, date: dateKey }).lean();
      const limit = await TimeLimitSetting.findOne({ childId }).lean();
      const { base, bonus, effective } = computeEffectiveMinutes(limit);


      const total = doc?.totalSeconds ?? 0;

      const byAppRaw = doc?.byApp ?? {};

      const byApp = Object.entries(byAppRaw)
        .map(([safeKey, secs]) => {
          // skip legacy nested objects like "com" → { google: {...} }
          if (typeof secs !== "number") return null;

          return {
            packageName: unpackKey(safeKey),
            seconds: Number(secs),
          };
        })
        .filter(Boolean)
        .sort((a, b) => b.seconds - a.seconds);

      let isActive = false;
      if (doc?.lastTickAt) {
        const now = Date.now();
        const last = new Date(doc.lastTickAt).getTime();
        if (now - last <= 70_000) {
          isActive = true;
        }
      }

      res.json({
        childId,
        date: dateKey,
        totalSeconds: total,
        dailyMinutes: effective,   // effective limit used by guard logic
        baseDailyMinutes: base,    
        bonusMinutes: bonus,       // optional extra info for UI
        byApp,
        isActive,
      });
    } catch (e) {
      next(e);
    }
  }
);

// summary last N days for weekly usage
r.get(
  "/summary",
  requireAuth,
  query("childId").optional().isMongoId(),
  query("range").optional().isString(),
  async (req, res, next) => {
    try {
      v(req, res);
      const childId = await resolveChildIdOr403(req);

      const range = String(req.query.range || "7d");
      const days = Math.max(1, parseInt(range, 10) || 7);

      const end = dayjs().tz().startOf("day");
      const start = end.subtract(days - 1, "day");

      const docs = await TimeUsageEntry.find({
        childId,
        date: {
          $gte: start.format("YYYY-MM-DD"),
          $lte: end.format("YYYY-MM-DD"),
        },
      }).lean();

      const byDate = {};
      for (let i = 0; i < days; i++) {
        const d = start.add(i, "day").format("YYYY-MM-DD");
        byDate[d] = 0;
      }
      for (const d of docs) {
        byDate[d.date] = Number(d.totalSeconds || 0);
      }

      const series = Object.keys(byDate)
        .sort()
        .map((d) => ({ date: d, totalSeconds: byDate[d] }));
      const totalSeconds = series.reduce((a, b) => a + b.totalSeconds, 0);

      res.json({ childId, days, totalSeconds, series });
    } catch (e) {
      next(e);
    }
  }
);

// per-app breakdown for a specific day 

r.get(
  "/by-app",
  requireAuth,
  query("childId").optional().isMongoId(),
  query("date").optional().isString(),
  async (req, res, next) => {
    try {
      v(req, res);
      const childId = await resolveChildIdOr403(req);
      const dateKey = (req.query.date && String(req.query.date)) || todayKey();

      const doc = await TimeUsageEntry.findOne({ childId, date: dateKey }).lean();

      const byAppRaw = doc?.byApp ?? {};
      const apps = Object.entries(byAppRaw)
        .map(([safeKey, secs]) => ({
          packageName: unpackKey(safeKey),
          seconds: Number(secs),
        }))
        .sort((a, b) => b.seconds - a.seconds);

      res.json({ childId, date: dateKey, apps });
    } catch (e) {
      next(e);
    }
  }
);

// history window 

r.get(
  "/history",
  requireAuth,
  query("childId").optional().isMongoId(),
  query("days").optional().isInt({ min: 1, max: 90 }),
  async (req, res, next) => {
    try {
      v(req, res);
      const childId = await resolveChildIdOr403(req);
      const days = Number(req.query.days || 30);

      const end = dayjs().tz().startOf("day");
      const start = end.subtract(days - 1, "day");

      const docs = await TimeUsageEntry.find({
        childId,
        date: {
          $gte: start.format("YYYY-MM-DD"),
          $lte: end.format("YYYY-MM-DD"),
        },
      }).lean();

      const series = [];
      const byDate = new Map();
      for (const d of docs) byDate.set(d.date, Number(d.totalSeconds || 0));

      for (let i = 0; i < days; i++) {
        const key = start.add(i, "day").format("YYYY-MM-DD");
        series.push({ date: key, totalSeconds: byDate.get(key) || 0 });
      }

      res.json({ childId, days, series });
    } catch (e) {
      next(e);
    }
  }
);

export default r;
