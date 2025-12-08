// src/routes/policy.js
import { Router } from "express";
import { query, validationResult } from "express-validator";
import { requireAuth } from "../middleware/authz.js";

import BlockEntry from "../models/BlockEntry.js";
import AppBlockEntry from "../models/AppBlockEntry.js";
import AppTempUnblock from "../models/AppTempUnblock.js";
import KeywordEntry from "../models/KeywordEntry.js";

import TimeLimitSetting from "../models/TimeLimitSetting.js";
import TimeUsageEntry from "../models/TimeUsageEntry.js";

import BedtimeSetting from "../models/BedtimeSetting.js";
import RemoteState from "../models/RemoteState.js";

import dayjs from "dayjs";
import utc from "dayjs/plugin/utc.js";
import timezone from "dayjs/plugin/timezone.js";

dayjs.extend(utc);
dayjs.extend(timezone);
dayjs.tz.setDefault("Asia/Kuala_Lumpur");

const r = Router();

const v = (req, res) => {
  const e = validationResult(req);
  if (!e.isEmpty()) return res.status(400).json({ errors: e.array() });
};

// Helper: parent may ask for specific child; child may ask only for self
async function resolveChildIdOr403(req) {
  const requested = req.query.childId;

  if (req.user.role === "Child") {
    // child will only always use own id, ignore provided childId
    return String(req.user._id);
  }

  // parent requested childId is required
  if (!requested) {
    const e = new Error("childId is required");
    e.status = 400;
    throw e;
  }

  // ensure requested child is in same family
  const { default: User } = await import("../models/User.js");
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

function bedtimeActiveNow(setting) {
  if (!setting || !setting.enabled) return false;

  const tz = setting.timezone || "Asia/Kuala_Lumpur";
  const now = dayjs().tz(tz);

  const [sh, sm] = (setting.start || "22:00").split(":").map(Number);
  const [eh, em] = (setting.end || "07:00").split(":").map(Number);

  const start = now.hour(sh).minute(sm).second(0);
  let end = now.hour(eh).minute(em).second(0);

  // If end is before start => crosses midnight
  if (end.isBefore(start)) {
    // add one day to end, representing "next day 06:00"
    end = end.add(1, "day");
  }

  // If now is before start but crosses midnight, check yesterday's window
  const nowBeforeStart = now.isBefore(start);
  const crossesMidnight =
    setting.end && setting.start && end.isAfter(start.add(1, "minute"));

  if (crossesMidnight && nowBeforeStart) {
    const yesterdayStart = start.subtract(1, "day");
    const yesterdayEnd = end.subtract(1, "day");
    return now.isAfter(yesterdayStart) && now.isBefore(yesterdayEnd);
  }

  return now.isAfter(start) && now.isBefore(end);
}

r.get(
  "/",
  requireAuth,
  query("childId").optional().isMongoId(),
  async (req, res, next) => {
    try {
      v(req, res);

      const childId = await resolveChildIdOr403(req);

      // ---- Pull data in parallel ----
      const [webRows, appRows, tempRows, keyRows, bedtimeDoc, remoteDoc] =
        await Promise.all([
          BlockEntry.find({ childId })
            .select("host path urlNormalized updatedAt")
            .lean(),
          AppBlockEntry.find({ childId })
            .select("packageName updatedAt")
            .lean(),
          AppTempUnblock.find({
            childId,
            until: { $gt: new Date() },
          })
            .select("packageName until updatedAt")
            .lean(),
          KeywordEntry.find({ childId })
            .select("keyword keywordLower updatedAt")
            .lean(),
          BedtimeSetting.findOne({ childId }).lean(),
          RemoteState.findOne({ childId }).lean(),
        ]);

      // Websites
      const websites = webRows.map((w) => ({
        host: w.host,
        path: w.path || "/",
        url: w.urlNormalized || undefined,
      }));

      // Apps minus active temp-unblocks
      const unblockSet = new Set(tempRows.map((u) => u.packageName));
      const apps = appRows
        .map((a) => a.packageName)
        .filter((pkg) => !unblockSet.has(pkg));

      // Keywords for lowercased list
      const keywords = keyRows
        .map((k) => (k.keywordLower || k.keyword || "").toLowerCase())
        .filter(Boolean);

      // Generate a date key in the format "YYYY-MM-DD"
      const dateKey = new Date().toISOString().slice(0, 10);
      // Load the time-limit rule for this child
      const set = await TimeLimitSetting.findOne({ childId }).lean();
      // Load today's screen-time usage for this child
      const usage = await TimeUsageEntry.findOne({
        childId,
        date: dateKey,
      }).lean();
      // Extract daily limit in minutes.
      const daily = set?.dailyMinutes ?? 0;
      // Extract total used time today in seconds.
      const used = usage?.totalSeconds ?? 0;
      // Compute the remaining time for today.
      const timeRemaining =
        daily <= 0 ? Number.MAX_SAFE_INTEGER : Math.max(0, daily * 60 - used);

      // Bedtime payload + active flag
      const bedtime =
        bedtimeDoc &&
        ({
          start: bedtimeDoc.start,
          end: bedtimeDoc.end,
          timezone: bedtimeDoc.timezone || "Asia/Kuala_Lumpur",
          enabled: !!bedtimeDoc.enabled,
        } || null);

      const bedtimeActiveNowFlag = bedtimeActiveNow(bedtimeDoc);

      // Remote state payload
      const remote = remoteDoc
        ? {
            locked: !!remoteDoc.locked,
            pauseNet: !!remoteDoc.pauseNet,
            forceLockUntil: remoteDoc.forceLockUntil
              ? remoteDoc.forceLockUntil.getTime()
              : null,
          }
        : {
            locked: false,
            pauseNet: false,
            forceLockUntil: null,
          };

      // Versioning
      const remoteTs = remoteDoc?.updatedAt?.getTime?.() ?? 0;
      const latestTs = Math.max(
        0,
        ...webRows.map((x) => x.updatedAt?.getTime?.() ?? 0),
        ...appRows.map((x) => x.updatedAt?.getTime?.() ?? 0),
        ...tempRows.map((x) => x.updatedAt?.getTime?.() ?? 0),
        ...keyRows.map((x) => x.updatedAt?.getTime?.() ?? 0),
        remoteTs
      );
      const version = `w${websites.length}-a${apps.length}-u${tempRows.length}-k${keywords.length}-${latestTs}`;

      return res.json({
        version,
        websites,
        apps,
        tempUnblocks: tempRows.map((u) => ({
          packageName: u.packageName,
          until: u.until,
        })),
        keywords,
        timeRemaining,
        bedtime,
        bedtimeActiveNow: bedtimeActiveNowFlag,
        bedtimeActive: bedtimeActiveNowFlag,

      
        remote,
      });
    } catch (e) {
      next(e);
    }
  }
);

export default r;
