// src/routes/keywords.js
import { Router } from "express";
import { body, query, param, validationResult } from "express-validator";
import { requireAuth, requireParent } from "../middleware/authz.js";
import KeywordEntry from "../models/KeywordEntry.js";
import KeywordSetting from "../models/KeywordSetting.js";

const r = Router();

const v = (req, res) => {
  const e = validationResult(req);
  if (!e.isEmpty()) {
    res.status(400).json({ errors: e.array() });
    return false;
  }
  return true;
};

// ensure child belongs to parent's family
async function ensureChildInFamilyOrThrow(user, childId) {
  const { default: User } = await import("../models/User.js");
  const kid = await User.findOne({ _id: childId, role: "Child" }).lean();
  if (!kid) {
    const e = new Error("Child not found");
    e.status = 404;
    throw e;
  }
  if (String(kid.familyId || "") !== String(user.familyId || "")) {
    const e = new Error("Child not in your family");
    e.status = 403;
    throw e;
  }
  return kid;
}

/** POST /keywords  { childId, keyword } */
r.post(
  "/",
  requireAuth,
  requireParent,
  body("childId").isMongoId(),
  body("keyword").isString().trim().isLength({ min: 1, max: 100 }),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;
      const { childId, keyword } = req.body;

      await ensureChildInFamilyOrThrow(req.user, childId);
      const kLower = keyword.toLowerCase();

      const doc = await KeywordEntry.findOneAndUpdate(
        { childId, keywordLower: kLower },
        {
          $setOnInsert: {
            childId,
            keyword,
            keywordLower: kLower,
            createdBy: req.user._id,
            source: "custom",
          },
        },
        { new: true, upsert: true }
      );

      return res.status(201).json(doc);
    } catch (e) {
      next(e);
    }
  }
);

/** GET /keywords?childId=... */
r.get(
  "/",
  requireAuth,
  query("childId").isMongoId(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const childId = req.query.childId;
      if (req.user.role === "Parent") {
        await ensureChildInFamilyOrThrow(req.user, childId);
      } else if (
        req.user.role === "Child" &&
        String(req.user._id) !== String(childId)
      ) {
        return res.status(403).json({ message: "Not allowed" });
      }

      const rows = await KeywordEntry.find({ childId })
        .sort({ keywordLower: 1 })
        .lean();

      return res.json(rows);
    } catch (e) {
      next(e);
    }
  }
);

/** DELETE /keywords/:id */
r.delete(
  "/:id",
  requireAuth,
  requireParent,
  param("id").isMongoId(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;
      const row = await KeywordEntry.findById(req.params.id).lean();
      if (!row) return res.status(404).json({ message: "Not found" });

      await ensureChildInFamilyOrThrow(req.user, row.childId);
      await KeywordEntry.deleteOne({ _id: row._id });

      return res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  }
);

/** GET /keywords/settings?childId=... */
r.get(
  "/settings",
  requireAuth,
  query("childId").isMongoId(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;
      const childId = req.query.childId;

      if (req.user.role === "Parent") {
        await ensureChildInFamilyOrThrow(req.user, childId);
      } else if (
        req.user.role === "Child" &&
        String(req.user._id) !== String(childId)
      ) {
        return res.status(403).json({ message: "Not allowed" });
      }

      const doc = await KeywordSetting.findOne({ childId }).lean();

      return res.json({
        childId,
        alertsEnabled: !!doc?.alertsEnabled,
        filterEnabled: doc?.filterEnabled ?? true,
      });
    } catch (e) {
      next(e);
    }
  }
);

/** PATCH /keywords/settings  { childId, alertsEnabled?, filterEnabled? } */
r.patch(
  "/settings",
  requireAuth,
  requireParent,
  body("childId").isMongoId(),
  body("alertsEnabled").optional().isBoolean(),
  body("filterEnabled").optional().isBoolean(),
  async (req, res, next) => {
    try {
      if (!v(req, res)) return;

      const { childId } = req.body;
      await ensureChildInFamilyOrThrow(req.user, childId);

      const update = {};
      if (typeof req.body.alertsEnabled === "boolean") {
        update.alertsEnabled = req.body.alertsEnabled;
      }
      if (typeof req.body.filterEnabled === "boolean") {
        update.filterEnabled = req.body.filterEnabled;
      }

      const doc = await KeywordSetting.findOneAndUpdate(
        { childId },
        { $setOnInsert: { childId }, $set: update },
        { new: true, upsert: true }
      ).lean();

      return res.json({
        childId,
        alertsEnabled: !!doc.alertsEnabled,
        filterEnabled: doc.filterEnabled ?? true,
      });
    } catch (e) {
      next(e);
    }
  }
);

export default r;
