// routes/bedtime.js
import express from "express";
import BedtimeSetting from "../models/BedtimeSetting.js";
import dayjs from "dayjs";
import utc from "dayjs/plugin/utc.js";
import timezone from "dayjs/plugin/timezone.js";
import { requireAuth } from "../middleware/authz.js";

dayjs.extend(utc);
dayjs.extend(timezone);

const router = express.Router();

router.use(requireAuth);

/* helpers for HH:mm */
const HHMM = /^[0-2]\d:[0-5]\d$/;

// Reuse the same style as policy.js: Parent → explicit childId, Child → self
async function resolveChildId(req) {
  const requested = (req.query.childId || req.body.childId || "").trim();

  if (req.user.role === "Child") {
    // child always uses own id
    return String(req.user._id || req.user.sub);
  }

  if (req.user.role === "Parent") {
    if (!requested) {
      const err = new Error("childId is required for parent role.");
      err.status = 400;
      throw err;
    }
    // Optionally ensure child belongs to same family – skipped here to keep it simple
    return requested;
  }

  const err = new Error("Unauthorized");
  err.status = 401;
  throw err;
}

// Single helper: is bedtime active right now?
function bedtimeActiveNow(setting, now = dayjs()) {
  if (!setting || !setting.enabled) return false;

  // Constant using Asia/Kuala Lumpur for bedtime checks
  const tz = "Asia/Kuala_Lumpur";
  const localNow = now.tz(tz);

  const [sh, sm] = (setting.start || "22:00").split(":").map(Number);
  const [eh, em] = (setting.end || "06:00").split(":").map(Number);

  if (setting.start === setting.end) {
    // if start time == end time means 24h lock, then return true
    return true;
  }

  const start = localNow.hour(sh).minute(sm).second(0).millisecond(0);
  let end = localNow.hour(eh).minute(em).second(0).millisecond(0);

  const crosses = end.isBefore(start) || end.isSame(start);

  if (crosses) {
    // e.g. 22:00 → 06:00
    if (localNow.isBefore(end)) {
      const yStart = start.subtract(1, "day");
      return localNow.isAfter(yStart) && localNow.isBefore(end);
    }
    end = end.add(1, "day");
  }

  return localNow.isAfter(start) && localNow.isBefore(end);
}

/* GET /api/bedtime?childId=... */
router.get("/", async (req, res, next) => {
  try {
    const childId = await resolveChildId(req);
    const setting = await BedtimeSetting.findOne({ childId }).lean();

    if (!setting) {
      console.log("[BEDTIME][GET] none for child", childId);
      return res.json({
        exists: false,
        childId,
        start: "22:00",
        end: "06:00",
        timezone: "Asia/Kuala_Lumpur",
        enabled: false,
        bedtimeActiveNow: false,
      });
    }

    // Determine whether bedtime is active right now.
    const active = bedtimeActiveNow(setting, dayjs());
    // Debug log: allows you to see bedtime evaluation in your server console
    console.log(
      "[BEDTIME][GET]",
      childId,
      "enabled=", !!setting.enabled,
      "start=", setting.start,
      "end=", setting.end,
      "active=", active
    );

    // Return bedtime policy data to the client as JSON
    res.json({
      exists: true,
      childId,
      start: setting.start,
      end: setting.end,
      timezone: "Asia/Kuala_Lumpur", // Fixed timezone used
      enabled: !!setting.enabled,
      bedtimeActiveNow: active,
      updatedAt: setting.updatedAt, // Timestamp when this record was last changed
    });
  } catch (err) {
    next(err);
  }
});

/* PUT /api/bedtime */
router.put("/", async (req, res, next) => {
  try {
    const childId = await resolveChildId(req);
    const { start, end, timezone: tz, enabled } = req.body || {};

    if (!HHMM.test(start || "") || !HHMM.test(end || "")) {
      const e = new Error("start and end must be HH:mm (24h) format");
      e.status = 400;
      throw e;
    }

    // Force the timeZone to Malaysia, not client request
    const timezoneName = "Asia/Kuala_Lumpur";

    // Save exactly what the client sends for enabled (default true if omitted)
    const nextEnabled =
      typeof enabled === "boolean" ? enabled : true;

    const doc = await BedtimeSetting.findOneAndUpdate(
      { childId },
      {
        $set: {
          start,
          end,
          timezone: timezoneName,
          enabled: nextEnabled,
        },
      },
      { new: true, upsert: true }
    ).lean();

    const active = bedtimeActiveNow(doc, dayjs());

    console.log(
      "[BEDTIME][PUT]",
      childId,
      "enabled=", nextEnabled,
      "start=", start,
      "end=", end,
      "activeNow=", active
    );

    res.json({
      message: "Bedtime saved",
      setting: doc,
      bedtimeActiveNow: active,
    });
  } catch (err) {
    next(err);
  }
});

/* DELETE /api/bedtime */
router.delete("/", async (req, res, next) => {
  try {
    const childId = await resolveChildId(req);
    await BedtimeSetting.deleteOne({ childId });
    console.log("[BEDTIME][DELETE]", childId);
    res.json({ message: "Bedtime removed", childId });
  } catch (err) {
    next(err);
  }
});

export default router;
